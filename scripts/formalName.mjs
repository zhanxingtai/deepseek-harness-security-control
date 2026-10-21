/**
 * formalName.mjs — marketplace formal display-name derivation.
 *
 * the plugin's formal name (marketplace display name)
 * follows the platform naming convention (formalName.mjs:5-25):
 *
 *     sst-security-control-dsh-v<major>.<minor>.<patch> 安全监控插件
 *
 * The version segment is derived from `package.json` `version` with the
 * prerelease suffix trimmed (`0.5.2-rc2` → `v0.5.2`, `1.0.0-alpha.1` →
 * `v1.0.0`). This must NEVER be hand-maintained — `scripts/prepare.mjs`
 * imports `deriveFormalName()` to stamp `lib/marketplace.manifest.json`
 * `displayName` and the shipped `locale/<lang>.json` `meta.title` files
 * (the real marketplace display-name contract, read by dsh-app-boot
 * `readPluginMeta` with `package.json` name/description as fallback).
 *
 * Consumers that cannot parse a well-formed semver triple get the
 * unversioned fallback instead of an exception — a display name must
 * always be derivable, even from a bogus version.
 */

export const FORMAL_NAME_PREFIX = 'sst-security-control-dsh'

// Full `major.minor.patch` (numeric triple, optional leading `v`) with an
// optional semver prerelease (`-rc2`, `-alpha.1`) or build (`+sha`)
// suffix. Anything else (empty, `1.2`, `abc`, …) is rejected → fallback.
const VERSION_TRIPLE_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/

/**
 * Derive the formal display name from a package version.
 *
 * @param {unknown} version `package.json` `version` (any value tolerated)
 * @returns {string} formal name; the unversioned
 *   `sst-security-control-dsh 安全监控插件` fallback when `version` is
 *   not a well-formed semver triple
 */
export function deriveFormalName(version) {
  const v = typeof version === 'string' ? version.trim() : ''
  const m = VERSION_TRIPLE_RE.exec(v)
  if (!m) {
    return `${FORMAL_NAME_PREFIX} 安全监控插件`
  }
  return `${FORMAL_NAME_PREFIX}-v${m[1]}.${m[2]}.${m[3]} 安全监控插件`
}
