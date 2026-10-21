/**
 * Data-leak detection flags (数据泄露监测统一标准 v0.2.0 §5.2).
 *
 * `deriveDataLeakFlags()` scans a command string (tool-call `command` param or
 * a subprocess argv joined with spaces) and returns the standard risk tags
 * the command exhibits:
 *
 *  - `data_exfiltration` — L1.1 transfer-tool features: curl upload/data
 *    flags, wget --post-file, scp, rsync/sftp/rclone remote copies, git push,
 *    PowerShell Invoke-WebRequest/Invoke-RestMethod -InFile, nc/socat pipes.
 *    The tag answers "is this an upload/transfer gesture"; destination
 *    classification happens here too: transfers whose visible destination is
 *    entirely internal (RFC1918 / loopback / link-local-adjacent intranet
 *    names / .internal|.local|.corp|.intra|.lan / bare single-label hosts)
 *    are NOT flagged, because normal backup/sync business must not light up
 *    exfil alerts (标准 §6.2 禁令 1 — 常见工具不得单独构成泄露判定).
 *    No visible destination (e.g. `git push`) → flagged, destination unknown.
 *  - `db_dump` — L3.1 dump-tool features: mysqldump/pg_dump/pg_dumpall/
 *    mongoexport/mongodump/redis-cli --rdb/sqlite3 .dump/bcp/SQL INTO
 *    OUTFILE. Host-default rules mirror real client behaviour: mysql/
 *    postgres/mongo/redis clients default to localhost, so no --host/-h flag
 *    means local backup → NOT flagged; an explicit external --host IS.
 *    sqlite3 .dump / bcp / INTO OUTFILE always flag (they carry no host
 *    signal worth distinguishing at warn level).
 *
 * Detection-only: callers merge these into `ctx.riskFlags`; every rule that
 * consumes them today is warn/advisory, so injection alone never changes an
 * execution result. Rules (not this module) own the whitelist semantics and
 * the confidence-appropriate decision (标准 §6.1).
 */

/** Upload/data-carrying curl flags (plain `-O`/`-o` downloads stay silent). */
const CURL_UPLOAD_RE = /\bcurl\b[^|\n]*?\s(-T\b|--upload-file\b|-d\b|--data\b|--data-binary\b|--data-ascii\b|--data-urlencode\b|-F\b|--form\b)/
const WGET_UPLOAD_RE = /\bwget\b[^|\n]*?\s--(?:post-file|body-file)\b/
const SCP_RE = /\bscp\b\s/
const RSYNC_REMOTE_RE = /\brsync\b[^|\n]*?\s(?![A-Za-z]:[\\/])(\S+@[^\s:]+:[^\s]|[^\s:]+::[^\s])/
const SFTP_RE = /\bsftp\b\s/
const RCLONE_RE = /\brclone\b[^|\n]*?\s(?![A-Za-z]:[\\/])[^\s]+:[^\s]/
const GIT_PUSH_RE = /\bgit\s+push\b/
const PS_UPLOAD_RE = /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^|\n]*?\s-InFile\b/
const NC_PIPE_RE = /\|\s*(?:nc|ncat|netcat)\b/
const SOCAT_RE = /\bsocat\b[^|\n]*?(STDIO|TCP[46]?:)/

/** Host tokens that can indicate a transfer destination. */
const URL_HOST_RE = /(?:https?|ftp|ftps|sftp|ssh|rsync|git):\/\/([^\s/?#]+)/g
const USER_AT_HOST_RE = /[\w.+-]+@([\w.+-]+):/g
const RSYNC_DAEMON_RE = /([\w.+-]+)::[\w]/g
const RCLONE_REMOTE_RE = /(?<![/\w])([A-Za-z][\w-]{1,31}):\/(?![/])/g
const IPV4_TOKEN_RE = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g
/** scp host:/path without user@ (`backup:/srv/…`). ≥2 chars before the colon
 *  excludes Windows drive letters (`C:/…`). */
const SCP_HOST_RE = /(?:^|\s)(?![A-Za-z]:[\\/])([\w.+-]{2,}):\//g

/** Internal destination classification (standard §5.4 `internal` tier). */
function isInternalHost(host: string): boolean {
  // Strip an explicit :port suffix first — `localhost:8080` is localhost.
  const h = host.trim().replace(/^\[|\]$/g, '').replace(/:\d+$/, '').toLowerCase()
  if (h === 'localhost' || h === '::1' || h === '0.0.0.0') return true
  if (/^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h)) return true
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true
  // 169.254.x.x (IMDS) is deliberately NOT internal — L1.5 treats it as a
  // sensitive destination.
  if (/\.(internal|local|corp|intra|lan)$/.test(h)) return true
  // Bare single-label hostnames (e.g. `backup`, `nas`) are intranet by
  // convention in shell-typed destinations.
  if (!h.includes('.') && !h.includes(':')) return true
  return false
}

function collectDestinationHosts(command: string): string[] {
  const hosts: string[] = []
  const collect = (re: RegExp, group: number) => {
    re.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = re.exec(command)) !== null) {
      const value = m[group]
      if (typeof value === 'string' && value.length > 0) hosts.push(value)
    }
  }
  collect(URL_HOST_RE, 1)
  collect(USER_AT_HOST_RE, 1)
  collect(RSYNC_DAEMON_RE, 1)
  collect(RCLONE_REMOTE_RE, 1)
  collect(IPV4_TOKEN_RE, 1)
  collect(SCP_HOST_RE, 1)
  return hosts
}

/** True when the command carries an upload gesture toward a non-internal /
 *  unknown destination. */
function hasExternalTransfer(command: string): boolean {
  const gesture =
    CURL_UPLOAD_RE.test(command) ||
    WGET_UPLOAD_RE.test(command) ||
    SCP_RE.test(command) ||
    RSYNC_REMOTE_RE.test(command) ||
    SFTP_RE.test(command) ||
    RCLONE_RE.test(command) ||
    GIT_PUSH_RE.test(command) ||
    PS_UPLOAD_RE.test(command) ||
    NC_PIPE_RE.test(command) ||
    SOCAT_RE.test(command)
  if (!gesture) return false
  const hosts = collectDestinationHosts(command)
  if (hosts.length === 0) return true // destination unknown → flag
  return hosts.some((h) => !isInternalHost(h))
}

const DUMP_TOOL_RE = /\b(mysqldump|pg_dump|pg_dumpall|mongoexport|mongodump)\b/
const REDIS_RDB_RE = /\bredis-cli\b[^|\n]*?--rdb\b/
const SQLITE_DUMP_RE = /\bsqlite3\b[^|\n]*?\s\.dump\b/
const BCP_RE = /\bbcp\b\s+[\w.$#]+\.[\w.$#]+/
const INTO_OUTFILE_RE = /\binto\s+(outfile|dumpfile)\b/i
/** Host-flag value that keeps a dump local (socket paths count as local). */
const LOCAL_HOST_VALUE_RE = /^(localhost|127\.0\.0\.1|::1|\/)/i

/**
 * mysql/postgres/mongo/redis clients default to localhost: an explicit
 * external --host/-h is the distinguishing signal, so "no host flag" is
 * treated as a local backup and stays unflagged.
 */
function hasExplicitRemoteDbHost(command: string): boolean {
  const flagRe = /(?:--host(?:=|\s+)|\s-h\s+)(\S+)/
  const m = flagRe.exec(command)
  if (!m) return false
  return !LOCAL_HOST_VALUE_RE.test(m[1])
}

/** True when the command looks like a DB/log dump toward a non-local target. */
function hasDbDump(command: string): boolean {
  if (DUMP_TOOL_RE.test(command)) return hasExplicitRemoteDbHost(command)
  if (REDIS_RDB_RE.test(command)) return hasExplicitRemoteDbHost(command)
  // sqlite3 .dump / bcp / INTO OUTFILE carry no usable host signal — flag at
  // warn level regardless (规则侧仍可用 paramsNotRegex 等做豁免).
  return SQLITE_DUMP_RE.test(command) || BCP_RE.test(command) || INTO_OUTFILE_RE.test(command)
}

/**
 * Derive data-leak risk tags from a command string. Returns a de-duplicated
 * subset of { data_exfiltration, db_dump }; empty for normal business
 * commands (downloads, local backups, internal syncs).
 */
export function deriveDataLeakFlags(command: string): string[] {
  if (typeof command !== 'string' || command.length === 0) return []
  if (command.length > 16 * 1024) return []
  const flags = new Set<string>()
  if (hasExternalTransfer(command)) flags.add('data_exfiltration')
  if (hasDbDump(command)) flags.add('db_dump')
  return [...flags]
}
