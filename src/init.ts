/**
 * Plugin bootstrap step 1 — env-guard + config integrity + schema
 * validation + draft merge. Runs BEFORE any collector is constructed so
 * that a hostile config / silent-injection env is rejected before
 * allocating resources.
 *
 * The function returns `undefined` when the plugin should NOT load
 * (config-disabled, integrity-failed, env-violation) — `apply()` simply
 * returns in that case without further work.
 *
 * Returns `{ config, debugLog }` on the happy path. The `debugLog`
 * handle is needed downstream by `bootstrap.ts` so error sites and
 * collectors write to the same operator-visible file.
 */
import type { Context } from './types/external.js'
import { runConfigIntegrityCheck } from './utils/configIntegrity.js'
import { checkPreloadEnv } from './index.js'
import { DebugLog } from './utils/debugLog.js'
import { validateConfig } from './config.schema.js'
import { normalizeConfig, inheritLegacyRequestBodyBudget, isModeExplicit, type Config as ConfigShape } from './config.js'
import { applyDraftToConfig, readDraftFile, resolveDraftPath } from './config/draft.js'

export interface InitResult {
  config: ConfigShape
  debugLog: DebugLog
  /**
   * Default-mode-from-policy seam.
   *
   * True iff the raw operator input explicitly sets
   * `intervention.mode` or top-level `mode` to `'audit' | 'enforce'`.
   * Bootstrap reads this and passes the negation as
   * `defaultModeFromPolicy` to `InterventionEngine`: when the
   * operator HAS explicitly set mode, the engine defers to the
   * operator's choice and ignores the policy file's `mode:` field.
   */
  modeIsExplicit: boolean
}

export function initializePluginContext(ctx: Context, rawConfig: unknown): InitResult | undefined {
  // Verify the loaded patch config has the expected structure and emit a
  // deterministic hash for cross-restart drift detection. The tool-stack
  // layer is already covered by SELF_PROTECTION_PATH_GUARD_033 (priority
  // 1500) — this startup check closes the "direct file edit + engine
  // restart" path.
  const configCheck = runConfigIntegrityCheck(rawConfig)
  if (!configCheck.ok) {
    ctx.logger.error(
      `[SecurityMonitor] config integrity FAILED — refusing to load: ${configCheck.issues.join('; ')}`,
    )
    return undefined
  }
  ctx.logger.info(
    `[SecurityMonitor] config integrity OK: hash=${configCheck.configHash.slice(0, 16)}… checks=${configCheck.checksPassed}`,
  )
  // Cross-restart config drift. Drift is a warning, not a
  // load refusal: a legitimate operator edit (e.g. flipping mode to
  // enforce) changes the hash by design, and refusing to load would lock
  // the host out of its own hardening path. The drift record is logged
  // loudly so an UNEXPECTED change is investigated.
  if (configCheck.configDrift?.driftDetected && configCheck.configDrift.issue) {
    ctx.logger.error(`[SecurityMonitor] ${configCheck.configDrift.issue}`)
  } else if (configCheck.configDrift && !configCheck.configDrift.persisted) {
    ctx.logger.warn(
      `[SecurityMonitor] config hash could not be persisted to ${configCheck.configDrift.stateFile} ` +
        '— cross-restart drift detection is degraded for this run',
    )
  }

  // Silent-injection env guards.
  //
  // These env vars are pre-Node-injection vectors:
  //   NODE_OPTIONS  — Node preloads a `--require` module BEFORE the plugin runs
  //   PYTHONSTARTUP / PYTHONNOUSERSITE — Python loads sitecustomize.py on every python invocation
  //   PYTHONPATH — prepended to sys.path
  //   LD_PRELOAD — glibc loads this .so into every dynamically linked process
  //
  // A hostile value here runs before any of our code, bypassing SPL
  // entirely. The plugin runs in the same process as the engine, so any of
  // these affects us directly. We refuse to load if any is set to a
  // non-whitelisted value — operators have to opt in explicitly via the
  // harness's documented env (e.g. `bwrap` wrappers, or explicit
  // NODE_OPTIONS=--require ./instrument.js) for the env to be honored.
  //
  // The check is best-effort: we log a clear error so operators can diagnose
  // the rejection, but the plugin still loads if the env is empty (the
  // common case).
  const envGuard = checkPreloadEnv()
  if (envGuard.violations.length > 0) {
    ctx.logger.error(
      `[SecurityMonitor] refusing to start: pre-Node-injection env vars are set: ${envGuard.violations.join(', ')}. ` +
        `These can hijack the plugin before it runs. Unset them or document them in the harness profile.`,
    )
    // Do NOT load the plugin — silent injection is too dangerous to log and continue.
    return undefined
  }

  // Install / deploy diagnostic log.
  // Constructed BEFORE schema validation and config normalization so
  // the schema_fallback and disabled_by_config breadcrumbs land
  // regardless of which path the operator takes. The path is pulled
  // directly from `rawConfig` because `config.collector.debugLogPath`
  // isn't available until after `normalizeConfig` runs; the env var
  // `SECURITY_MONITOR_DEBUG_LOG` is also accepted as an escape hatch
  // for cases where rawConfig shape is suspect (Schemastery reject).
  const debugLogPathFromRaw = (() => {
    if (rawConfig && typeof rawConfig === 'object' && 'collector' in rawConfig) {
      const c = (rawConfig as { collector?: unknown }).collector
      if (c && typeof c === 'object' && 'debugLogPath' in c) {
        const p = (c as { debugLogPath?: unknown }).debugLogPath
        if (typeof p === 'string') return p
      }
    }
    return process.env['SECURITY_MONITOR_DEBUG_LOG'] ?? ''
  })()
  const debugLog: DebugLog = new DebugLog({
    path: debugLogPathFromRaw,
    logger: ctx.logger,
  })

  // Marketplace Schemastery Config (see ./config.schema.ts).
  // Run Schema validation first as a fast-fail for misspelled sub-keys,
  // enum typos, and out-of-range numeric defaults. On success the
  // Schemastery-filled object is passed to `normalizeConfig` so the
  // Schema defaults become authoritative — `normalizeConfig` only adds
  // the deep fields the Schema doesn't model (AuthConfig discriminated
  // union, hostname fallback, networkCapture scanIntervalMs clamp).
  // On failure the plugin falls back to `normalizeConfig(rawConfig)`
  // directly with a single warn.
  // Legacy request-budget inheritance must run BEFORE Schemastery
  // validation: the Schema carries the 64 KiB default for
  // `maxRequestBodyBytes`, which would otherwise mask a legacy config's
  // intent (`maxBodyBytes` only) and silently shrink its request budget.
  const rawForValidation = inheritLegacyRequestBodyBudget(rawConfig)
  const schemaValidated = validateConfig(rawForValidation)
  if (schemaValidated === undefined) {
    ctx.logger.warn(
'[SecurityMonitor] Schemastery Config validation failed; '+
        'falling back to legacy normalizeConfig. ' +
'See the plugin README for the strict-vs-loose contract.',
    )
    // breadcrumb so operators can correlate a misbehaving marketplace
    // install with a Schemastery reject. The full `rawConfig` is NOT
    // included (it may carry credentials); only the failure marker + a
    // structural fingerprint of the shape is recorded.
    debugLog.write('schema_fallback', {
      reason: 'Schemastery Config validation failed; legacy normalizeConfig engaged',
    })
  } else {
    ctx.logger.debug(
      `[SecurityMonitor] Schemastery Config validated (mode=${schemaValidated.mode ??'audit'}); ` +
        'Schema defaults applied before normalizeConfig.',
    )
  }
  // `let` — the draft merge below reassigns the merged result.
  let config: ConfigShape = normalizeConfig(schemaValidated ?? rawConfig)

  if (!config.enabled) {
    debugLog.write('disabled_by_config', {
      enabled: config.enabled,
      reason: 'config.enabled === false; plugin will not load',
    })
    ctx.logger.info('[SecurityMonitor] disabled by config')
    return undefined
  }

  // Config draft merge on startup.
  //
  // The settings-page Config tab writes operator edits to
  // `~/.dsh/security-monitor-config.draft.json` (see `src/config/draft.ts`).
  // Drafts never hot-apply — the next `apply()` call reads the file and
  // deep-merges it on top of the patch YAML's normalized result.
  //
  // We DO NOT delete the file (per §3 "不删除草稿文件"):
  //   - A stale draft simply re-applies on the next start (the same
  //     patch produces the same result), which is the right behavior.
  //   - Operators can `rm` the file manually when they want to
  //     revert to the patch YAML.
  //   - On parse failure we log a single warn and continue with
  //     the patch YAML — a bad draft cannot block startup.
  {
    const draft = readDraftFile()
    if (draft && draft.patch && typeof draft.patch === 'object') {
      // `merged` used to be computed for the
      // warn-line identity check but never assigned back — the draft
      // merge was silently discarded and restarts always ran the patch
      // YAML config (operator-visible symptom: "draft saved, restart,
      // nothing changed"). The identity check was also vacuous
      // (`applyDraftToConfig` always returns a fresh object), so it is
      // gone; the presence of a readable envelope IS the apply signal.
      config = applyDraftToConfig(config, draft.patch as Record<string, unknown>)
      ctx.logger.warn(
        `[SecurityMonitor] Applied config draft from ${resolveDraftPath()} ` +
          `(operator=${draft.operator || 'anonymous'}, patchedAt=${draft.patchedAt})`,
      )
    }
  }

  return { config, debugLog, modeIsExplicit: isModeExplicit(rawConfig) }
}