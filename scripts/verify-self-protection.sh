#!/usr/bin/env bash
#
# c: end-to-end Self-Protection verification harness.
#
# Each scenario sends a synthetic `agent_tool_call` (or `message_write`)
# event through the plugin's InterventionEngine and asserts that the
# resulting `block_code` matches the rule under test. Modeled after
# 24-prompt self-protection test suite — see scripts/verify-self-protection-runner.ts.
#
# This is the dev-time / CI-time counterpart to the install-time
# `verify-install.sh`. The install script covers packaging; this one
# covers the *content* of the protection rules.
#
# Run from the repo root:
#   bash scripts/verify-self-protection.sh
#
# Exits 0 on success, non-zero on any failure (and prints a summary).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
TS_SCRIPT="$REPO_ROOT/scripts/verify-self-protection-runner.ts"

if ! command -v node >/dev/null 2>&1; then
  echo "FAIL: node is required (this script drives the InterventionEngine via Node)"
  exit 1
fi

if [[ ! -f "$REPO_ROOT/lib/index.js" ]]; then
  echo "Building TypeScript first..."
  (cd "$REPO_ROOT" && pnpm build >/dev/null 2>&1) || {
    echo "FAIL: pnpm build failed"
    exit 1
  }
fi

# Delegate to a Node runner that knows how to instantiate the engine
# against the default policy and run a JSON-defined list of scenarios.
echo "[verify-self-protection] running 24 self-protection scenarios..."
exec node "$TS_SCRIPT" "$@"
