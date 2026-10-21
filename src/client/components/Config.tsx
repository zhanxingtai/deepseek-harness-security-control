/**
 * Config tab — metadata-driven rewrite (+
 * mechanism clause).
 *
 * Form field definitions live in `src/client/config/fields.ts`
 * (CONFIG_FIELD_METADATA) — this component renders purely from that
 * table and never hardcodes a field list. The parity test in
 * `tests/configParity.test.ts` pins the metadata key set against the
 * host-side Config leaf keys, so the form cannot drift from the host
 * surface.
 *
 * Danger-key mechanism (hard requirement): on Save, `resolveDangerHits`
 * (derived from the metadata `danger` flags + DANGER_FIELD_VALUES)
 * checks whether the draft turns `mode` into 'enforce' or
 * `intervention.failStrategy` into 'fail_closed'. ANY hit opens the
 * confirmation dialog unconditionally — regardless of validation
 * warnings — and Cancel leaves the draft unsaved.
 *
 * Save semantics are UNCHANGED: Save writes the draft through
 * `saveConfigDraft` (restart-to-apply); livePatch stays a host-side
 * RPC surface and this form does not persist anything itself.
 */
import {
  createElement,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type ReactNode,
} from 'react'
import { createPortal } from 'react-dom'
import type {
  ConfigDraftResult,
  ConfigDraftStatus,
  ConfigPatch,
  ConfigSnapshot,
  ConfigValidationResult,
  SecurityMonitorBridge,
} from '../wire.js'
import type { LocaleKey } from '../locales.js'
import { Banner, Button } from './primitives.js'
import {
  CONFIG_FIELD_METADATA,
  CONFIG_SECTIONS,
  readFieldValue,
  resolveDangerHits,
  type ConfigFieldMeta,
} from '../config/fields.js'

export interface ConfigProps {
  bridge: SecurityMonitorBridge
  t: (key: LocaleKey, params?: Record<string, string | number>) => string
}

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | {
      kind: 'viewing' | 'editing' | 'validating' | 'saving' | 'success' | 'error-form'
      snapshot: ConfigSnapshot
      draft: ConfigPatch
      /** Latest validation result — null when not yet run for this draft. */
      validation: ConfigValidationResult | null
      /** Pending save error from the previous attempt — null when none. */
      saveError: string | null
      /** Saved path from the previous save — null when no save yet. */
      savedPath: string | null
    }

interface FormStateShape {
  kind: 'viewing' | 'editing' | 'validating' | 'saving' | 'success' | 'error-form'
  snapshot: ConfigSnapshot
  draft: ConfigPatch
  validation: ConfigValidationResult | null
  saveError: string | null
  savedPath: string | null
}

const FORM_KINDS: ReadonlySet<State['kind']> = new Set([
  'viewing',
  'editing',
  'validating',
  'saving',
  'success',
  'error-form',
])

function isFormStateKind(kind: State['kind']): boolean {
  return FORM_KINDS.has(kind)
}

const DEBOUNCE_MS = 500

/** Success-banner auto-dismiss window. 8 s balances "the operator
 *  has time to read the path + restart hint" with "the banner does
 *  not linger until the next edit". The dismiss button (×) cancels
 *  the timer immediately. */
const SUCCESS_BANNER_AUTO_DISMISS_MS = 8_000

/** The confirmation dialog has two trigger sources: unconditional
 *  danger hits (mode → enforce / failStrategy → fail_closed) and
 *  validation warnings. Both reuse the same dialog chrome. */
interface ConfirmState {
  kind: 'danger' | 'warnings'
  /** Locale message keys describing each danger hit (danger only). */
  dangerMessages: ReadonlyArray<LocaleKey>
  warnings: string[]
}

export function Config({ bridge, t }: ConfigProps): ReactNode {
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [reloading, setReloading] = useState(false)
  const [pendingDraft, setPendingDraft] = useState<ConfigDraftStatus | null>(null)
  const [confirm, setConfirm] = useState<ConfirmState | null>(null)
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(new Set())
  const [copiedMessage, setCopiedMessage] = useState<string | null>(null)
  /** Tracks whether the operator has explicitly dismissed the
   *  current success banner. Re-arms every time the form transitions
   *  back to a fresh `kind: 'success'` (i.e. another Save). */
  const [successDismissed, setSuccessDismissed] = useState<boolean>(false)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const validateSeqRef = useRef(0)
  const successTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  // Copy-JSON banner auto-dismiss. Each new click resets the 3 s
  // timer and unmount clears any pending dismissal so the banner
  // does not linger for the rest of the session.
  const copyBannerTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const scheduleBannerClear = useCallback((): void => {
    if (copyBannerTimerRef.current !== null) {
      clearTimeout(copyBannerTimerRef.current)
    }
    copyBannerTimerRef.current = setTimeout(() => {
      setCopiedMessage(null)
      copyBannerTimerRef.current = null
    }, 3000)
  }, [])
  useEffect(() => {
    return () => {
      if (copyBannerTimerRef.current !== null) {
        clearTimeout(copyBannerTimerRef.current)
        copyBannerTimerRef.current = null
      }
    }
  }, [])

  /**
   * Initial load — pull both `getConfig()` and `getConfigDraftStatus()`
   * concurrently so the pending-draft banner can appear on first paint.
   */
  useEffect(() => {
    let cancelled = false
    setState({ kind: 'loading' })
    Promise.all([bridge.getConfig(), bridge.getConfigDraftStatus()])
      .then(([snapshot, draft]) => {
        if (cancelled) return
        if (draft && draft.path) setPendingDraft(draft)
        setState({
          kind: 'viewing',
          snapshot,
          draft: {},
          validation: null,
          saveError: null,
          savedPath: null,
        })
      })
      .catch((err: unknown) => {
        if (cancelled) return
        const message = err instanceof Error ? err.message : String(err)
        setState({
          kind: 'error',
          message: `${t('config_load_error')} [${message}]`,
        })
      })
    return () => {
      cancelled = true
    }
  }, [bridge, t])

  /**
   * Success-banner auto-dismiss. Whenever the form transitions to
   * `kind: 'success'` (i.e. a fresh save result) the banner re-arms:
   * the `successDismissed` flag resets to false and a timer schedules
   * a dismissal at +8 s. The timer is cleared on the next transition
   * (so a churn of saves does not extend the lifetime unpredictably)
   * and on unmount. The explicit `×` button cancels the same timer.
   */
  useEffect(() => {
    // After `state.kind === 'success'`, TS narrows `state` to the
    // success branch (carries `savedPath`). The earlier `as Extract<…>`
    // casts produced `never` because the success branch in `State`
    // unions `kind` over multiple strings.
    const isSuccess =
      state.kind === 'success' &&
      typeof state.savedPath === 'string' &&
      state.savedPath.length > 0
    if (!isSuccess) return
    setSuccessDismissed(false)
    if (successTimerRef.current) clearTimeout(successTimerRef.current)
    successTimerRef.current = setTimeout(() => {
      setSuccessDismissed(true)
      successTimerRef.current = null
    }, SUCCESS_BANNER_AUTO_DISMISS_MS)
    return () => {
      if (successTimerRef.current) {
        clearTimeout(successTimerRef.current)
        successTimerRef.current = null
      }
    }
  }, [state])

  /**
   * Debounced validation. The seq counter discards out-of-order results
   * so a slow earlier validateConfigPatch cannot overwrite a later one.
   */
  const scheduleValidate = useCallback(
    (draft: ConfigPatch) => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
      debounceRef.current = setTimeout(() => {
        const seq = ++validateSeqRef.current
        setState((prev) =>
          prev.kind === 'viewing' ||
          prev.kind === 'editing' ||
          prev.kind === 'validating' ||
          prev.kind === 'error-form'
            ? { ...prev, kind: 'validating', validation: null }
            : prev,
        )
        bridge
          .validateConfigPatch(draft)
          .then((validation) => {
            if (seq !== validateSeqRef.current) return
            setState((prev) =>
              prev.kind === 'validating' || prev.kind === 'editing'
                ? { ...prev, kind: 'editing', validation }
                : prev,
            )
          })
          .catch((err: unknown) => {
            if (seq !== validateSeqRef.current) return
            const message = err instanceof Error ? err.message : String(err)
            setState((prev) =>
              prev.kind === 'validating'
                ? {
                    ...prev,
                    kind: 'error-form',
                    validation: {
                      ok: false,
                      errors: [message],
                      warnings: [],
                      normalized: null,
                    },
                  }
                : prev,
            )
          })
      }, DEBOUNCE_MS)
    },
    [bridge],
  )

  /**
   * Sub-block shallow merge for the draft.
   *
   * The Config form surfaces nested sub-blocks (e.g. `intervention.mode`
   * and `intervention.policyPaths` are two fields in the same `intervention`
   * sub-block). `emit()` for each dotted key returns a partial sub-block
   * patch (`{intervention: {mode: 'enforce'}}`), so a plain top-level
   * spread (`{...prev.draft, ...next}`) would replace the whole
   * `intervention` object and silently drop sibling edits made earlier in
   * the same session.
   *
   * The server-side `applyDraftToConfig` already does a proper sub-block
   * shallow merge (`src/config/draft.ts:161`), so the persisted draft on
   * disk is correct — but the in-memory `draft` state in the UI loses
   * edits, which means the `validateConfigPatch` preview, the `Copy JSON`
   * output, and the saved draft all reflect only the latest edit. This
   * helper keeps the in-memory draft in lockstep with the on-disk shape.
   */
  const mergeDraftPatch = useCallback(
    (base: ConfigPatch, next: ConfigPatch): ConfigPatch => {
      const out: Record<string, unknown> = { ...base }
      for (const [k, v] of Object.entries(next)) {
        const existing = out[k]
        if (
          v && typeof v === 'object' && !Array.isArray(v) &&
          existing && typeof existing === 'object' && !Array.isArray(existing)
        ) {
          out[k] = { ...(existing as Record<string, unknown>), ...(v as Record<string, unknown>) }
        } else {
          out[k] = v
        }
      }
      return out as ConfigPatch
    },
    [],
  )

  /**
   * Field change handler. Updates the local draft and triggers the
   * debounced validator. Switches state to `editing` if it was
   * `viewing` / `error-form` / `success`.
   */
  const onFieldChange = useCallback(
    (next: ConfigPatch) => {
      setCopiedMessage(null)
      setState((prev) => {
        if (
          prev.kind !== 'viewing' &&
          prev.kind !== 'editing' &&
          prev.kind !== 'error-form' &&
          prev.kind !== 'success'
        ) {
          return prev
        }
        const merged = mergeDraftPatch(prev.draft, next)
        return { ...prev, kind: 'editing', draft: merged, saveError: null, savedPath: null }
      })
      // Schedule the next validation pass — read the merged draft
      // from the latest state to avoid a stale closure.
      setState((prev) => {
        if (
          prev.kind !== 'editing' &&
          prev.kind !== 'viewing' &&
          prev.kind !== 'error-form' &&
          prev.kind !== 'success'
        ) {
          return prev
        }
        const merged = mergeDraftPatch(prev.draft, next)
        scheduleValidate(merged)
        return prev
      })
    },
    [scheduleValidate, mergeDraftPatch],
  )

  const doSave = useCallback(
    (draft: ConfigPatch): void => {
      bridge
        .saveConfigDraft(draft)
        .then((result: ConfigDraftResult) => {
          setState((prev) => {
            if (prev.kind !== 'saving') return prev
            if (!result.ok) {
              return {
                ...prev,
                kind: 'error-form',
                saveError: result.error ?? 'unknown error',
              }
            }
            // Refresh the pending-draft banner so it reflects the
            // freshly-saved file (patchedAt bumped by the host).
            bridge
              .getConfigDraftStatus()
              .then((status) => {
                if (status && status.path) setPendingDraft(status)
              })
              .catch(() => {
                /* non-fatal: banner still shows the just-saved path */
              })
            return {
              ...prev,
              kind: 'success',
              savedPath: result.path,
              saveError: null,
            }
          })
        })
        .catch((err: unknown) => {
          const message = err instanceof Error ? err.message : String(err)
          setState((prev) =>
            prev.kind === 'saving' ? { ...prev, kind: 'error-form', saveError: message } : prev,
          )
        })
    },
    [bridge],
  )

  /**
   * Save handler — mechanism clause: the dangerous-key check runs
   * FIRST and unconditionally. Any hit (mode → enforce,
   * intervention.failStrategy → fail_closed) opens the confirmation
   * dialog regardless of validation warnings; only when there are no
   * danger hits do warnings trigger the (same) dialog. With neither,
   * the save proceeds straight away.
   *
   * The state snapshot is read from `stateRef` so the click handler
   * does NOT call `setConfirm` from inside the `setState` updater —
   * React may re-run updaters under concurrent rendering, which would
   * fire the dialog twice. `stateRef` is kept in sync via a tiny
   * `useEffect` so the click handler always sees the latest committed
   * state.
   */
  const stateRef = useRef<State>(state)
  useEffect(() => {
    stateRef.current = state
  }, [state])

  /**
   * Apply a `SaveResult` to the form: handle the dialog signal,
   * transition State, and fire doSave when result is 'saving'. The
   * `kind: 'error-form'` and `kind: 'confirm'` branches both keep the
   * draft (operator can keep editing); only `kind: 'saving'` consumes
   * the draft into a write to the host.
   */
  const applySaveResult = useCallback(
    (result: SaveResult, draft: ConfigPatch): void => {
      if (result.kind === 'saving') {
        setState((prev) =>
          prev.kind === 'viewing' ||
          prev.kind === 'editing' ||
          prev.kind === 'validating' ||
          prev.kind === 'success' ||
          prev.kind === 'error-form'
            ? { ...prev, kind: 'saving' }
            : prev,
        )
        doSave(draft)
        return
      }
      if (result.kind === 'error-form') {
        setState((prev) =>
          prev.kind === 'viewing' ||
          prev.kind === 'editing' ||
          prev.kind === 'validating' ||
          prev.kind === 'success' ||
          prev.kind === 'saving'
            ? {
                ...prev,
                kind: 'error-form',
                validation: result.validation,
                saveError: null,
                savedPath: null,
              }
            : prev,
        )
        return
      }
      // kind: 'confirm' — open the dialog (danger or warnings); state
      // stays 'editing' so the operator can still tweak the draft.
      // The validation result already landed via scheduleValidate's
      // then-handler or the re-trigger path in onSave, so no setState
      // is needed here.
      setConfirm(result.confirm)
    },
    [doSave],
  )

  const onSave = useCallback(() => {
    const cur = stateRef.current
    if (cur.kind !== 'viewing' && cur.kind !== 'editing' && cur.kind !== 'error-form') {
      return
    }
    const draft = cur.draft

    // If validation has not yet run (first Save in this session, or
    // every edit since the last validation), trigger it now and wait
    // for the result before deciding what to do. Without this, the
    // save would race the debounced validator and the operator would
    // see the error-form state with no feedback.
    if (cur.validation === null) {
      setState((prev) =>
        prev.kind === 'viewing' ||
        prev.kind === 'editing' ||
        prev.kind === 'success' ||
        prev.kind === 'error-form'
          ? { ...prev, kind: 'validating', validation: null }
          : prev,
      )
      setTimeout(() => {
        bridge
          .validateConfigPatch(draft)
          .then((validation) => {
            const result = resolveSaveWithValidation(draft, validation)
            // The validating → saving transition commits first; then
            // we apply the result. applySaveResult itself transitions
            // to 'saving' / 'error-form' / opens confirm.
            setState((prev) =>
              prev.kind === 'validating'
                ? { ...prev, validation }
                : prev,
            )
            applySaveResult(result, draft)
          })
          .catch((err: unknown) => {
            const message = err instanceof Error ? err.message : String(err)
            setState((prev) =>
              prev.kind === 'validating'
                ? {
                    ...prev,
                    kind: 'error-form',
                    validation: {
                      ok: false,
                      errors: [message],
                      warnings: [],
                      normalized: null,
                    },
                  }
                : prev,
            )
          })
      }, DEBOUNCE_MS)
      return
    }

    // Validation already resolved — proceed directly.
    const result = resolveSaveWithValidation(draft, cur.validation)
    applySaveResult(result, draft)
  }, [bridge, doSave, applySaveResult])

  const onConfirmSave = useCallback(() => {
    const cur = stateRef.current
    setConfirm(null)
    if (cur.kind !== 'viewing' && cur.kind !== 'editing' && cur.kind !== 'error-form') {
      return
    }
    const draft = cur.draft
    // Confirm button = operator accepted the danger / warning and wants
    // to write. The dialog has already done its job; go straight to
    // `saving`. Re-running resolveSaveWithValidation here would just
    // re-derive the same dialog and never reach `doSave`.
    setState((prev) =>
      prev.kind === 'viewing' ||
      prev.kind === 'editing' ||
      prev.kind === 'validating' ||
      prev.kind === 'success' ||
      prev.kind === 'error-form'
        ? { ...prev, kind: 'saving' }
        : prev,
    )
    doSave(draft)
  }, [doSave])

  const onCancelSave = useCallback(() => {
    // Cancel keeps the draft intact but does NOT save.
    setConfirm(null)
  }, [])

  const onDismissSuccess = useCallback(() => {
    if (successTimerRef.current) {
      clearTimeout(successTimerRef.current)
      successTimerRef.current = null
    }
    setSuccessDismissed(true)
  }, [])

  const onReset = useCallback(() => {
    setCopiedMessage(null)
    if (successTimerRef.current) {
      clearTimeout(successTimerRef.current)
      successTimerRef.current = null
    }
    setSuccessDismissed(false)
    setState((prev) =>
      prev.kind === 'viewing' ||
      prev.kind === 'editing' ||
      prev.kind === 'validating' ||
      prev.kind === 'error-form' ||
      prev.kind === 'success'
        ? { ...prev, kind: 'viewing', draft: {}, validation: null, saveError: null, savedPath: null }
        : prev,
    )
  }, [])

  const onReload = useCallback(() => {
    setReloading(true)
    Promise.all([bridge.getConfig(), bridge.getConfigDraftStatus()])
      .then(([snapshot, draft]) => {
        if (draft && draft.path) setPendingDraft(draft)
        else setPendingDraft(null)
        setState({
          kind: 'viewing',
          snapshot,
          draft: {},
          validation: null,
          saveError: null,
          savedPath: null,
        })
      })
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err)
        setState({ kind: 'error', message: `${t('config_load_error')} [${message}]` })
      })
      .finally(() => {
        setReloading(false)
      })
  }, [bridge, t])

  /** Copy JSON — serialises the EFFECTIVE config (snapshot overlaid
   *  with the draft) so the operator can paste it into a patch file.
   *  Clipboard is best-effort (host may deny permission). */
  const onCopyJson = useCallback(() => {
    setState((prev) => {
      if (!isFormStateKind(prev.kind)) return prev
      const shape = prev as FormStateShape
      const merged: Record<string, unknown> = {}
      for (const field of CONFIG_FIELD_METADATA) {
        // Skip `locked` fields (`collector.redactRawParams`,
        // `inlineGuards.*`, the four guard `*.enabled` switches,
        // `stdioMirror.enabled`, etc.) — `normalizeConfig` force-
        // asserts them at apply time, so pasting their effective
        // values into `cordis.patch.yml` is misleading: the operator
        // sees "I set `engineLaunchers: [my-list]`" but the runtime
        // ends up with `[...fallback, ...my-list]`. Omitting the
        // locked entries makes the copied JSON a faithful "what
        // you'll see after the host's normalise pass".
        if (field.locked) continue
        const value = readFieldValue(shape.snapshot, shape.draft, field.key)
        if (value === undefined) continue
        const dot = field.key.indexOf('.')
        if (dot < 0) {
          merged[field.key] = value
        } else {
          const block = field.key.slice(0, dot)
          const leaf = field.key.slice(dot + 1)
          const bag = (merged[block] ??= {}) as Record<string, unknown>
          bag[leaf] = value
        }
      }
      const text = JSON.stringify(merged, null, 2)
      const clipboard = (
        globalThis as { navigator?: { clipboard?: { writeText(s: string): Promise<void> } } }
      ).navigator?.clipboard
      if (clipboard && typeof clipboard.writeText === 'function') {
        clipboard
          .writeText(text)
          // Generic `copy` keys replace the tab-prefixed `config_copy_json_*`
          // triple so every "copy this content" surface in the plugin
          // translates consistently. The success / failure banner
          // auto-dismisses after 3 s.
          .then(() => {
            setCopiedMessage(t('copy_ok'))
            scheduleBannerClear()
          })
          .catch((err: unknown) => {
            setCopiedMessage(
              t('copy_fail', {
                error: err instanceof Error ? err.message : String(err),
              }),
            )
            scheduleBannerClear()
          })
      } else {
        setCopiedMessage(t('copy_fail', { error: 'clipboard unavailable' }))
        scheduleBannerClear()
      }
      return prev
    })
  }, [t])

  const toggleSection = useCallback((sectionId: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev)
      if (next.has(sectionId)) {
        next.delete(sectionId)
      } else {
        next.add(sectionId)
      }
      return next
    })
  }, [])

  // Hooks must run in the same order on every render — derive the
  // snapshot-derived locals BEFORE any early return so React's hook
  // count stays stable when `state.kind` flips between loading /
  // viewing / error / etc.
  const formState: FormStateShape = isFormStateKind(state.kind)
    ? (state as FormStateShape)
    : {
        kind: 'viewing',
        snapshot: null as unknown as ConfigSnapshot,
        draft: {},
        validation: null,
        saveError: null,
        savedPath: null,
      }
  const validation = formState.validation
  const errors = validation?.errors ?? []
  const warnings = validation?.warnings ?? []
  const hasErrors = errors.length > 0
  // Dirty = the draft, when overlaid on the snapshot, produces a config
  // that differs from the snapshot alone. A naive "draft has any keys"
  // check treats "type a value, then type it back" as a real edit and
  // leaves the Save button enabled to write a no-op draft. Iterate
  // every visible field, compute effective-vs-baseline, return true on
  // the first real change. String arrays compare element-wise; objects
  // don't appear in the form (no sub-sub-block fields), so a flat
  // compare is sufficient.
  const isDirty = useMemo(() => {
    if (!formState.snapshot) return false
    const baselineDraft: ConfigPatch = {}
    for (const field of CONFIG_FIELD_METADATA) {
      if (field.locked) continue
      const effective = readFieldValue(formState.snapshot, formState.draft, field.key)
      const baseline = readFieldValue(formState.snapshot, baselineDraft, field.key)
      if (!configValueEquals(effective, baseline)) return true
    }
    return false
  }, [formState.snapshot, formState.draft])

  // Render branches — placed AFTER all hooks so React's hook count
  // stays stable across state transitions.
  if (state.kind === 'loading') {
    return createElement(
      'div',
      { className: 'dsh-secmon-config', 'data-component': 'config' },
      createElement(Banner, { level: 'info', message: t('loading') }),
    )
  }
  if (state.kind === 'error') {
    return createElement(
      'div',
      { className: 'dsh-secmon-config', 'data-component': 'config' },
      createElement(Banner, { level: 'error', message: state.message }),
      createElement(
        Button,
        { onClick: onReload, disabled: reloading, children: t('config_reload') },
      ),
    )
  }

  return createElement(
    'div',
    { className: 'dsh-secmon-config', 'data-component': 'config' },
    // Top action bar: hint on the left, three buttons on the right
    // (Undo = green, Copy JSON = green, Save = blue primary).
    createElement(
      'div',
      { className: 'dsh-secmon-config-toolbar', 'data-component': 'config-toolbar' },
      createElement(
        'div',
        { className: 'dsh-secmon-config-toolbar-left' },
        createElement(
          'span',
          { 'data-component': 'config-reload-wrap' },
          createElement(Button, {
            onClick: onReload,
            disabled: reloading,
            children: reloading ? t('config_reloading') : t('config_reload'),
          }),
        ),
        createElement(
          'span',
          { className: 'dsh-secmon-config-readonly-hint', 'data-component': 'config-hint' },
          t('config_readonly_hint'),
        ),
      ),
      createElement(
        'div',
        { className: 'dsh-secmon-config-toolbar-right' },
        createElement(Button, {
          onClick: onReset,
          disabled: !isDirty || formState.kind === 'saving',
          variant: 'success',
          children: t('config_undo'),
        }),
        createElement(Button, {
          onClick: onCopyJson,
          variant: 'success',
          // Collapsed from `config_copy_json` to the shared `copy` key.
          // The Config toolbar keeps its text button (to match
          // Undo / Save) but the translation source for "copy" is
          // now shared across every copy affordance in the plugin.
          children: t('copy'),
        }),
        createElement(
          'span',
          { 'data-component': 'config-save-draft' },
          createElement(Button, {
            onClick: onSave,
            disabled:
              hasErrors || formState.kind === 'saving' || formState.kind === 'validating' || !isDirty,
            variant: 'primary',
            children: formState.kind === 'saving' ? t('config_saving') : t('config_save_draft'),
          }),
        ),
      ),
    ),
    copiedMessage
      ? createElement(
          'div',
          { 'data-component': 'config-copied-banner' },
          createElement(Banner, { level: 'info', message: copiedMessage }),
        )
      : null,
    pendingDraft && pendingDraft.path
      ? createElement(
          'div',
          { 'data-component': 'config-draft-banner' },
          createElement(Banner, {
            level: 'info',
            message: pendingDraftBannerMessage(pendingDraft, t),
          }),
        )
      : null,
    formState.kind === 'success' && formState.savedPath && !successDismissed
      ? createElement(
          'div',
          {
            className: 'dsh-secmon-config-saved-banner',
            'data-component': 'config-saved-banner',
            role: 'status',
          },
          createElement(
            'span',
            { className: 'dsh-secmon-config-saved-banner-icon', 'aria-hidden': 'true' },
            '✓',
          ),
          createElement(
            'span',
            { className: 'dsh-secmon-config-saved-banner-text' },
            t('config_draft_saved', { path: formState.savedPath }),
          ),
          createElement(
            'button',
            {
              type: 'button',
              className: 'dsh-secmon-config-saved-banner-dismiss',
              'data-component': 'config-saved-banner-dismiss',
              onClick: onDismissSuccess,
              title: t('config_saved_banner_dismiss'),
              'aria-label': t('config_saved_banner_dismiss'),
            },
            '×',
          ),
        )
      : null,
    formState.kind === 'error-form' && formState.saveError
      ? createElement(
          'div',
          { 'data-component': 'config-save-error-banner' },
          createElement(Banner, {
            level: 'error',
            message: t('config_draft_save_failed', { error: formState.saveError }),
          }),
        )
      : null,
    createElement(FormSections, {
      snapshot: formState.snapshot,
      draft: formState.draft,
      onFieldChange,
      collapsed,
      onToggleSection: toggleSection,
      t,
    }),
    createElement(ValidationPanel, {
      kind: formState.kind,
      errors,
      warnings,
      t,
    }),
    confirm
      ? createElement(ConfirmDialog, {
          confirm,
          onConfirm: onConfirmSave,
          onCancel: onCancelSave,
          t,
        })
      : null,
  )
}

/** Shared save gate logic — extracted so both onSave (when validation
 * is already resolved) and onConfirmSave can call it without duplicating
 * the danger/warnings confirm dialog logic. The `SaveResult` discriminated
 * union keeps the dialog signal OUT of the `State` type; callers run
 * `setConfirm` themselves when the result is `kind: 'confirm'`. */
type SaveResult =
  | { kind: 'saving' }
  | { kind: 'error-form'; validation: ConfigValidationResult }
  | { kind: 'confirm'; confirm: ConfirmState }

function resolveSaveWithValidation(
  draft: ConfigPatch,
  validation: ConfigValidationResult,
): SaveResult {
  if (validation.errors.length > 0) {
    return { kind: 'error-form', validation }
  }
  const dangerHits = resolveDangerHits(draft)
  if (dangerHits.length > 0) {
    return {
      kind: 'confirm',
      confirm: {
        kind: 'danger',
        dangerMessages: dangerHits.map((h) => h.message),
        warnings: validation.warnings,
      },
    }
  }
  if (validation.warnings.length > 0) {
    return {
      kind: 'confirm',
      confirm: {
        kind: 'warnings',
        dangerMessages: [],
        warnings: validation.warnings,
      },
    }
  }
  return { kind: 'saving' }
}

function pendingDraftBannerMessage(
  status: ConfigDraftStatus,
  t: (k: LocaleKey, params?: Record<string, string | number>) => string,
): string {
  const base = t('config_draft_banner_pending', { patchedAt: status.patchedAt })
  if (status.operator) {
    return `${base} ${t('config_draft_banner_by', { operator: status.operator })}`
  }
  return base
}

/** Shallow value comparison for the dirty-state check. The Config form
 *  only edits primitive fields and string[] (csv) values — no
 *  sub-sub-block objects — so a flat compare handles every field. The
 *  array branch compares element-wise so reordering or trimming a
 *  csv field actually counts as a real change (reference equality
 *  would be too lax; JSON.stringify would mask the order). */
function configValueEquals(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
    return true
  }
  return false
}

interface FormSectionsProps {
  snapshot: ConfigSnapshot
  draft: ConfigPatch
  onFieldChange: (patch: ConfigPatch) => void
  collapsed: ReadonlySet<string>
  onToggleSection: (sectionId: string) => void
  t: (k: LocaleKey, params?: Record<string, string | number>) => string
}

/** Render one collapsible panel per CONFIG_SECTIONS entry; each
 *  panel's field rows come from CONFIG_FIELD_METADATA filtered by
 *  section — the component holds no field definitions of its own.
 *  All `visibility: 'advanced'` fields and `advancedOnly: true`
 *  sections are permanently hidden from the form. The metadata
 *  table still carries the full key set (the parity test in
 *  `tests/configParity.test.ts` requires it), so removing the
 *  field rows does not drift the host ↔ client surface. Operators
 *  needing tuning knobs should edit the patch file directly. */
function FormSections({
  snapshot,
  draft,
  onFieldChange,
  collapsed,
  onToggleSection,
  t,
}: FormSectionsProps): ReactNode {
  return createElement(
    'div',
    { className: 'dsh-secmon-config-form', 'data-component': 'config-form' },
    CONFIG_SECTIONS.map((section) => {
      if (section.advancedOnly) return null
      const fields = CONFIG_FIELD_METADATA.filter((f) => {
        if (f.section !== section.id) return false
        if (f.visibility === 'advanced') return false
        return true
      })
      // Skip sections with no visible fields.
      if (fields.length === 0) return null
      const isCollapsed = collapsed.has(section.id)
      return createElement(
        'section',
        {
          key: section.id,
          className:
            'dsh-secmon-config-section' +
            (section.id === 'inlineGuards' ? ' dsh-secmon-config-inline-locked' : ''),
          'data-component': `config-section-${section.id}`,
        },
        createElement(
          'button',
          {
            type: 'button',
            className: 'dsh-secmon-config-section-header',
            'aria-expanded': !isCollapsed,
            onClick: () => onToggleSection(section.id),
          },
          createElement(
            'span',
            { className: 'dsh-secmon-config-section-chevron' },
            isCollapsed ? '▸' : '▼',
          ),
          createElement(
            // Uppercasing is the host theme's job (text-transform) —
            // the DOM keeps the locale text verbatim.
            'span',
            { className: 'dsh-secmon-config-section-name' },
            t(section.label),
          ),
          createElement(
            'span',
            { className: 'dsh-secmon-config-section-count' },
            ` (${t('config_section_count', { n: fields.length })})`,
          ),
          section.id === 'inlineGuards'
            ? createElement(
                'span',
                { className: 'dsh-secmon-config-lock', title: t('config_inline_locked_no_edit') },
                '🔒',
              )
            : null,
        ),
        isCollapsed
          ? null
          : createElement(
              'div',
              { className: 'dsh-secmon-config-section-body' },
              fields.map((field) =>
                createElement(FieldRow, {
                  key: field.key,
                  field,
                  snapshot,
                  draft,
                  onFieldChange,
                  t,
                }),
              ),
            ),
      )
    }),
  )
}

interface FieldRowProps {
  field: ConfigFieldMeta
  snapshot: ConfigSnapshot
  draft: ConfigPatch
  onFieldChange: (patch: ConfigPatch) => void
  t: (k: LocaleKey, params?: Record<string, string | number>) => string
}

/** One metadata-driven field row: label + dotted key on the left,
 *  kind-specific control on the right, help / warning text under the
 *  control. */
function FieldRow({ field, snapshot, draft, onFieldChange, t }: FieldRowProps): ReactNode {
  const effective = readFieldValue(snapshot, draft, field.key)
  const dependsOnValue = field.dependsOn
    ? readFieldValue(snapshot, draft, field.dependsOn)
    : undefined
  const disabled = field.dependsOn !== undefined && dependsOnValue === false

  const emit = (value: unknown): void => {
    const dot = field.key.indexOf('.')
    if (dot < 0) {
      onFieldChange({ [field.key]: value } as ConfigPatch)
    } else {
      const block = field.key.slice(0, dot)
      const leaf = field.key.slice(dot + 1)
      onFieldChange({ [block]: { [leaf]: value } } as ConfigPatch)
    }
  }

  // locked fields render as read-only text — no inputs, so the
  // safety net cannot be edited from the form.
  const control: ReactNode = field.locked
    ? createElement(
        'span',
        { className: 'dsh-secmon-config-locked-value' },
        Array.isArray(effective) ? effective.join(', ') : String(effective ?? t('config_value_empty')),
      )
    : renderControl(field, effective, disabled, emit, t)

  return createElement(
    'div',
    {
      className:
        'dsh-secmon-config-field-row' +
        (field.danger ? ' dsh-secmon-config-field-row--danger' : ''),
      'data-component': `config-field-${field.key.replace(/\./g, '-')}`,
    },
    createElement(
      'div',
      { className: 'dsh-secmon-config-field-label' },
      createElement(
        'div',
        { className: 'dsh-secmon-config-field-label-text' },
        t(field.label),
        field.danger
          ? createElement(
              'span',
              { className: 'dsh-secmon-config-danger-badge' },
              ` ${t('config_danger_badge')}`,
            )
          : null,
      ),
      createElement('code', { className: 'dsh-secmon-config-field-key' }, field.key),
    ),
    createElement(
      'div',
      { className: 'dsh-secmon-config-field-control' },
      control,
      field.danger && field.warning && !field.locked
        ? createElement(
            'div',
            { className: 'dsh-secmon-config-warning' },
            `⚠ ${t(field.warning)}`,
          )
        : null,
      !field.danger && field.help
        ? createElement('div', { className: 'dsh-secmon-config-help' }, t(field.help))
        : null,
    ),
  )
}

function renderControl(
  field: ConfigFieldMeta,
  effective: unknown,
  disabled: boolean,
  emit: (value: unknown) => void,
  t: (k: LocaleKey, params?: Record<string, string | number>) => string,
): ReactNode {
  switch (field.kind) {
    case 'boolean':
      return createElement(
        'label',
        { className: 'dsh-secmon-field dsh-secmon-field-bool' },
        createElement('input', {
          type: 'checkbox',
          checked: Boolean(effective),
          disabled,
          onChange: (e: ChangeEvent<HTMLInputElement>) =>
            emit(Boolean((e.target as HTMLInputElement).checked)),
        }),
        // Green on/off caption per the baseline (green only when on;
        // the off state stays gray via the base class).
        createElement(
          'span',
          {
            className:
              'dsh-secmon-config-bool-state' +
              (effective ? ' dsh-secmon-config-bool-state--on' : ''),
          },
          effective ? t('config_on') : t('config_off'),
        ),
      )
    case 'number':
      return createElement('input', {
        type: 'number',
        className: 'dsh-secmon-config-input',
        value: Number(effective ?? 0),
        disabled,
        onChange: (e: ChangeEvent<HTMLInputElement>) => {
          const next = Number((e.target as HTMLInputElement).value)
          emit(Number.isFinite(next) ? next : 0)
        },
      })
    case 'enum':
      return createElement(
        'select',
        {
          className: 'dsh-secmon-config-input',
          value: String(effective ?? ''),
          disabled,
          onChange: (e: ChangeEvent<HTMLSelectElement>) =>
            emit((e.target as HTMLSelectElement).value),
        },
        (field.enumValues ?? []).map((v) => createElement('option', { key: v, value: v }, v)),
      )
    case 'string':
    default: {
      const text = Array.isArray(effective)
        ? effective.join(', ')
        : String(effective ?? '')
      return createElement('input', {
        type: 'text',
        className: 'dsh-secmon-config-input',
        value: text,
        disabled,
        onChange: (e: ChangeEvent<HTMLInputElement>) => {
          const raw = (e.target as HTMLInputElement).value
          emit(field.csv ? raw.split(',').map((s) => s.trim()).filter(Boolean) : raw)
        },
      })
    }
  }
}

// The on/off caption next to boolean checkboxes renders via
// t('config_on') / t('config_off'); the base class is the gray
// (label-secondary) tone and the `--on` modifier paints the green
// success colour (see .dsh-secmon-config-bool-state--on in styles.ts).

interface ValidationPanelProps {
  kind: State extends { kind: infer K } ? K : never
  errors: string[]
  warnings: string[]
  t: (k: LocaleKey, params?: Record<string, string | number>) => string
}

function ValidationPanel({ kind, errors, warnings, t }: ValidationPanelProps): ReactNode {
  if (kind === 'validating') {
    return createElement(Banner, { level: 'info', message: t('config_validation_pending') })
  }
  if (errors.length === 0 && warnings.length === 0) {
    return null
  }
  return createElement(
    'div',
    { className: 'dsh-secmon-config-validation', 'data-component': 'config-validation' },
    errors.length > 0
      ? createElement(
          'div',
          { className: 'dsh-secmon-config-validation-errors' },
          createElement('h4', null, t('config_validation_errors')),
          createElement(
            'ul',
            null,
            errors.map((e, i) => createElement('li', { key: i }, e)),
          ),
        )
      : null,
    warnings.length > 0
      ? createElement(
          'div',
          { className: 'dsh-secmon-config-validation-warnings' },
          createElement('h4', null, t('config_validation_warnings')),
          createElement(
            'ul',
            null,
            warnings.map((w, i) => createElement('li', { key: i }, w)),
          ),
        )
      : null,
  )
}

interface ConfirmDialogProps {
  confirm: ConfirmState
  onConfirm: () => void
  onCancel: () => void
  t: (k: LocaleKey, params?: Record<string, string | number>) => string
}

/** Save confirmation — danger hits (unconditional) and validation
 *  warnings share the dialog chrome; danger renders its own title and
 *  the per-field danger messages. The dialog renders as a
 *  fixed-position centered modal over a semi-transparent backdrop,
 *  portal-mounted on document.body so it floats above page content.
 *  Escape and backdrop click cancel; the existing class names (and
 *  the data-component=config-confirm-dialog hook the tests query)
 *  are preserved. */
function ConfirmDialog({ confirm, onConfirm, onCancel, t }: ConfirmDialogProps): ReactNode {
  const isDanger = confirm.kind === 'danger'
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [onCancel])
  if (typeof document === 'undefined') return null
  return createPortal(
    createElement(
      'div',
      {
        className: 'dsh-secmon-confirm-modal',
        'data-component': 'config-confirm-dialog',
      },
      createElement('div', {
        className: 'dsh-secmon-confirm-overlay',
        'aria-hidden': 'true',
        onClick: onCancel,
      }),
      createElement(
        'div',
        { className: 'dsh-secmon-confirm-dialog', role: 'dialog', 'aria-modal': 'true' },
        createElement(
          'h3',
          null,
          isDanger ? t('config_confirm_danger_title') : t('config_confirm_save_with_warnings_title'),
        ),
        createElement(
          'p',
          null,
          isDanger
            ? t('config_confirm_danger_body')
            : t('config_confirm_save_with_warnings_body', { n: confirm.warnings.length }),
        ),
        isDanger && confirm.dangerMessages.length > 0
          ? createElement(
              'ul',
              null,
              confirm.dangerMessages.map((m, i) => createElement('li', { key: i }, t(m))),
            )
          : null,
        !isDanger && confirm.warnings.length > 0
          ? createElement(
              'ul',
              null,
              confirm.warnings.map((w, i) => createElement('li', { key: i }, w)),
            )
          : null,
        isDanger && confirm.warnings.length > 0
          ? createElement(
              'ul',
              null,
              confirm.warnings.map((w, i) => createElement('li', { key: `w-${i}` }, w)),
            )
          : null,
        createElement(
          'div',
          { className: 'dsh-secmon-confirm-dialog-actions' },
          createElement(
            'span',
            { 'data-component': 'config-confirm-save' },
            createElement(Button, {
              onClick: onConfirm,
              variant: 'primary',
              children: t('config_confirm_save_with_warnings_continue'),
            }),
          ),
          createElement(Button, {
            onClick: onCancel,
            children: t('config_confirm_save_with_warnings_cancel'),
          }),
        ),
      ),
    ),
    document.body,
  )
}
