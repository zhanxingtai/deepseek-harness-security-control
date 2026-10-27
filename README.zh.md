# sst-security-control-dsh

[English](README.md) | [简体中文](README.zh.md)

面向 DeepSeek Harness（`dsh`）的开源安全监控插件，提供本地风险检测、安全事件记录及高风险操作阻断。

**特性**：开箱即用，默认本地独立运行，无需注册账号，不连接云端服务。

## 主要能力 <!-- intent:what-it-does -->

- 智能体会话及行为事件记录（NDJSON 格式）
- 高危动作（反弹 shell、敏感文件访问等）在 `enforce` 模式下阻断，其余行为仅标记告警
- 运行状态与事件查看面板

## 安装 <!-- intent:install -->

**界面安装**：选择「添加插件」，输入 `install/sst-security-control-dsh-<version>.tgz` 路径即可。

**命令安装**：

```bash
# 1. 构建安装包
npm install --legacy-peer-deps
npm run build

# 2. 上传 tarball 到目标服务器
scp install/sst-security-control-dsh-<version>.tgz root@server:~/.dsh/

# 3. 在服务器上安装
pnpm dsh plugin --profile web add /path/to/sst-security-control-dsh-<version>.tgz
```

> `--profile web` 为目标 profile,按实际环境替换。

本地开发加载：

```bash
# 将插件链接到 profile 的 node_modules
cd ~/.dsh/profiles/<profile>
pnpm link /path/to/sst-security-control-dsh

# 应用插件补丁
pnpm dsh --profile <profile> --patch /path/to/sst-security-control-dsh/cordis.patch.yml
```

## 卸载

```bash
pnpm dsh plugin --profile web remove sst-security-control-dsh
```

## 配置

`cordis.patch.yml` 为唯一配置入口。关键选项：

<!-- source: cordis.patch.yml -->

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `intervention.mode` | `enforce` | 策略执行模式：`audit`（仅记录）或 `enforce`（阻断）。 |
| `enabled` | `true` | 总开关 |
| `collector.localOutputPath` | `~/.dsh/security-events.jsonl` | 事件日志路径 |
| `collector.externallyManagedLog` | `false` | 声明审计日志的轮转/删除由外部工具接管：文件生命周期异常只告警，不再产生 integrity 缺口事件 |
| `runtimeHooks.enabledAtSubprocess` | `true` | 启用子进程 spawn 拦截 |
| `runtimeHooks.blockAtSubprocess` | `false` | 在 `enforce` 模式下阻断被拒的子进程 |
| `intervention.failStrategy` | `fail_open` | 干预引擎故障/超时时的策略（`fail_open` 放行 / `fail_closed` 阻断） |
| `runtimeHooks.failOpenOnError` | `true` | 运行时钩子出错时放行，不因插件异常锁死宿主 |

## 自定义 SPL 规则

策略文件为 YAML 或 JSON（`apiVersion: security.use/v2`）。规则示例见 `policies/default-policy.spl.yaml`。

## 安全事件

事件为 NDJSON 行，`src/utils/schema.ts` 进行校验。事件类型包括：

- `agent_session_start` / `agent_start` / `agent_stop`
- `agent_tool_call` / `agent_tool_result`
- `runtime_spawn_intent` / `runtime_spawn_denied`
- `runtime_resolve_intent` / `runtime_resolve_denied`
- `security_audit`（内嵌守卫命中、循环检测、令牌异常）

## 后续计划

- [x] **1.0.0 · 事件采集 + 可观测 + 规则分析**：NDJSON 事件流、Control UI 面板、SPL 规则安全分析
- [ ] **1.1.0 · 语义识别 SDK**：在现有 SPL 规则引擎旁接入独立语义识别 SDK，提升检测能力

## 项目主页

- 官网：[https://www.zhihuizhanxing.com](https://www.zhihuizhanxing.com)
- 源码：[https://github.com/zhanxingtai/deepseek-harness-security-control](https://github.com/zhanxingtai/deepseek-harness-security-control)
- X（Twitter）：[@StarSightTec](https://x.com/StarSightTec)
- 微信公众号：

  ![微信公众号](assets/wechat-mp-qr.jpg)

## 支持

发现安全漏洞或需要紧急支持，请通过邮件联系（请勿在 GitHub issue 公开披露安全细节）：

- 安全邮箱：<support@zhihuizhanxing.com>

普通使用问题与功能请求走 GitHub Issues。

## 许可证 <!-- intent:license -->

[Apache-2.0](LICENSE) — 依赖声明见 `package.json`。