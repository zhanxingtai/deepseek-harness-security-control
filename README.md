# sst-security-control-dsh

[English](README.md) | [简体中文](README.zh.md)

Open-source security monitoring plugin for DeepSeek Harness (`dsh`), providing local risk detection, security event logging, and blocking of high-risk operations.

**Highlights**: works out of the box, runs fully local by default, no account registration, no cloud connectivity.

## What it does <!-- intent:what-it-does -->

- Records agent sessions and tool/agent behaviour as an NDJSON event stream
- Blocks high-risk actions (reverse shells, sensitive-file access, …) in `enforce` mode; everything else is only flagged
- Exposes runtime status and a live event viewer in the Control UI

## Install <!-- intent:install -->

**From the UI**: choose "Add plugin" and point it at `install/sst-security-control-dsh-<version>.tgz`.

**From the CLI**:

```bash
# 1. Build the install bundle
npm install --legacy-peer-deps
npm run build

# 2. Copy the tarball to the target server
scp install/sst-security-control-dsh-<version>.tgz root@server:~/.dsh/

# 3. Install it on the server
pnpm dsh plugin --profile web add /path/to/sst-security-control-dsh-<version>.tgz
```

> `--profile web` is the target profile — replace it with your own.

Local development load:

```bash
# Link the plugin into the profile's node_modules
cd ~/.dsh/profiles/<profile>
pnpm link /path/to/sst-security-control-dsh

# Apply the plugin patch
pnpm dsh --profile <profile> --patch /path/to/sst-security-control-dsh/cordis.patch.yml
```

## Uninstall

```bash
pnpm dsh plugin --profile web remove sst-security-control-dsh
```

## Configuration

`cordis.patch.yml` is the single configuration entry point. Key options:

<!-- source: cordis.patch.yml -->

| Option | Default | Description |
|------|--------|------|
| `intervention.mode` | `enforce` | Policy enforcement mode: `audit` (record only) or `enforce` (block). |
| `enabled` | `true` | Master switch |
| `collector.localOutputPath` | `~/.dsh/security-events.jsonl` | Event log path |
| `runtimeHooks.enabledAtSubprocess` | `true` | Enable subprocess spawn interception |
| `runtimeHooks.blockAtSubprocess` | `false` | Block denied subprocesses when running in `enforce` mode |
| `intervention.failStrategy` | `fail_open` | Behaviour when the intervention engine fails or times out (`fail_open` = allow, `fail_closed` = block) |
| `runtimeHooks.failOpenOnError` | `true` | Allow on runtime-hook errors so a plugin fault can't lock up the host |

## Custom SPL rules

Policy files are YAML or JSON (`apiVersion: security.use/v2`). See `policies/default-policy.spl.yaml` for a worked example.

## Security events

Events are NDJSON lines, validated by `src/utils/schema.ts`. Event types include:

- `agent_session_start` / `agent_start` / `agent_stop`
- `agent_tool_call` / `agent_tool_result`
- `runtime_spawn_intent` / `runtime_spawn_denied`
- `runtime_resolve_intent` / `runtime_resolve_denied`
- `security_audit` (embedded guard hits, loop detection, token anomalies)

## Roadmap

- [x] **1.0.0 · Event collection + observability + rule analysis**: NDJSON event stream, Control UI panel, SPL rule security analysis
- [ ] **1.1.0 · Semantic recognition SDK**: plug a standalone semantic recognition SDK alongside the existing SPL rule engine to improve detection coverage

## Project home

- Website: [https://www.zhihuizhanxing.com](https://www.zhihuizhanxing.com)
- Source: [https://github.com/zhanxingtai/deepseek-harness-security-control](https://github.com/zhanxingtai/deepseek-harness-security-control)
- X: [@StarSightTec](https://x.com/StarSightTec)
- WeChat Official Account:

  ![WeChat Official Account](assets/wechat-mp-qr.jpg)

## Support

If you find a security vulnerability or need urgent support, contact us by email (please do not disclose security details in a public GitHub issue):

- Security email: <support@zhihuizhanxing.com>

General usage questions and feature requests go to GitHub Issues.

## License <!-- intent:license -->

[Apache-2.0](LICENSE) — dependency declarations live in `package.json`.