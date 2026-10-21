#!/usr/bin/env node
/**
 * Inspect the local NDJSON security event file written by sst-security-control-dsh.
 *
 * Usage:
 *   node scripts/inspect-events.mjs [path]
 *
 * Defaults to ~/.dsh/security-events.jsonl on Unix and %USERPROFILE%\.dsh\security-events.jsonl on Windows.
 *
 * 2026-09-26 X6 A2: stdio mirror events are now interleaved with the
 * host plugin's events in the SAME NDJSON file (`stdioMirror.outputPath`
 * defaults to `collector.localOutputPath`). A single file walk covers
 * both host-plugin and wrapper-side events; no sibling file is read.
 * Operators who explicitly pointed `stdioMirror.outputPath` at a
 * separate volume must inspect that file directly.
 *
 * 2026-09-26 X6 E2-2: events are also clustered by origin (host-plugin
 * vs stdio-mirror wrapper) using the `event_type` prefix and the
 * `collection_method` field. After the per-type tally, an origin
 * section surfaces the host/wrapper split so operators can see at a
 * glance how much of the file is host-side audit vs raw byte-level
 * stdio capture.
 */
import { readFileSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const inputPath = process.argv[2] ?? join(homedir(), '.dsh', 'security-events.jsonl')

if (!existsSync(inputPath)) {
  console.error(`Event file not found: ${inputPath}`)
  process.exit(1)
}

const lines = readFileSync(inputPath, 'utf8')
  .split('\n')
  .map((line) => line.trim())
  .filter(Boolean)

const events = lines.map((line, index) => {
  try {
    return JSON.parse(line)
  } catch (error) {
    console.error(`Failed to parse line ${index + 1}: ${line.slice(0, 80)}`)
    throw error
  }
})

const byType = Object.create(null)
for (const event of events) {
  const type = event.event_type ?? 'unknown'
  byType[type] = (byType[type] ?? 0) + 1
}

// 2026-09-26 X6 E2-2: cluster by origin. The stdio mirror wrapper
// stamps three event types — `runtime_stdio_mirror` (per-chunk),
// `runtime_stdio_mirror_exit` (per child process), `runtime_stdio_mirror_error`
// (spawn / parse / pump failures). Everything else originates from the
// host plugin's collectors (ApplicationCollector / NetworkHttpCollector /
// RuntimeHook / LocalNdjsonSink). We bucket both ways for the audit
// summary:
//   - by event_type prefix (most robust: the wrapper's types all share
//     the `runtime_stdio_mirror` namespace regardless of collection_method)
//   - by collection_method (cross-check; the wrapper always stamps
//     `stdio_mirror`, host plugin uses `agent_api` / `fs_observed` /
//     `process_monitor` / etc.)
const MIRROR_TYPE_PREFIX = 'runtime_stdio_mirror'
const byOrigin = { host: 0, mirror: 0 }
const byCollectionMethod = Object.create(null)
let mirrorWrapperPids = new Set()
for (const event of events) {
  const type = event.event_type ?? 'unknown'
  if (typeof type === 'string' && type.startsWith(MIRROR_TYPE_PREFIX)) {
    byOrigin.mirror += 1
  } else {
    byOrigin.host += 1
  }
  const method = event.collection_method ?? 'unknown'
  byCollectionMethod[method] = (byCollectionMethod[method] ?? 0) + 1
  // Surface the unique wrapper PIDs so operators can tell how many
  // distinct wrapper processes contributed events. The host's
  // `wrapper_pid` is always undefined; only mirror events carry it.
  if (typeof event.wrapper_pid === 'number') {
    mirrorWrapperPids.add(event.wrapper_pid)
  }
}

console.log(`Total events: ${events.length}`)
console.log('By event_type:')
for (const [type, count] of Object.entries(byType).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${type}: ${count}`)
}

console.log('\nBy origin (X6 A2 / E2-2):')
console.log(`  host (ApplicationCollector + RuntimeHook + sinks): ${byOrigin.host}`)
console.log(`  stdio mirror (wrapper, runtime_stdio_mirror*):       ${byOrigin.mirror}`)
if (mirrorWrapperPids.size > 0) {
  console.log(`    unique wrapper_pids: ${[...mirrorWrapperPids].sort((a, b) => a - b).join(', ')}`)
}

console.log('\nBy collection_method:')
for (const [method, count] of Object.entries(byCollectionMethod).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${method}: ${count}`)
}

if (events.length > 0) {
  console.log('\nMost recent event:')
  console.log(JSON.stringify(events[events.length - 1], null, 2))
}
