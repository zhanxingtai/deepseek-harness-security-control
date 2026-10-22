# DeepSeek Harness Security Control - Agent Guidelines

## 1. 构建约定（强制）

### 1.1 包管理器与安装

本项目使用 **pnpm 10**（CI 经 `pnpm/action-setup@v4` 固定），Node **22/24** 矩阵。

```bash
pnpm install --frozen-lockfile
```

`.npmrc` 已固化 `auto-install-peers=false` + `strict-peer-dependencies=false`：peer 依赖含私有 `@deepseek-ai/*` 作用域，在公网 registry 404，**不要**改为 npm 或开启 peer 自动安装。

### 1.2 构建

```bash
pnpm build        # tsc -b + node scripts/build-client.mjs（产物在 lib/，被 gitignore）
pnpm test         # pretest 会自动先跑 build，再 vitest run
pnpm verify       # 7 个 verify 门（见 §4），全过才算可打包
pnpm run pack     # npm pack --pack-destination install（产物 install/*.tgz，被 gitignore）
                   # 注意：**必须** `pnpm run pack`，裸 `pnpm pack` 是 pnpm 内置命令，不认
                   # --pack-destination，会把产物丢到 cwd。这是历史上 release job 一直
                   # 打包失败的根因——CI 第一次执行到这里才暴露。
```

`prepack` 钩子会自动重跑 prepare + 全部 verify 门——**手动 `npm pack` 也绕不过验收**。

### 1.3 禁止事项

- 不要把 `file:` / 绝对路径依赖加进 package.json（CI 的 `open-source-hygiene` job 会拒）。
- 不要把 `lib/`、`install/*.tgz` 提交进仓库（均已被 gitignore）。

## 2. 验证清单

改动后必须本地全绿再推送：

- [ ] `pnpm build` 成功（`tsc --noEmitOnError` 等价的 `-b` 构建）
- [ ] `pnpm test` 全绿（macOS/Windows 行为差异见 §6 已知事项）
- [ ] `pnpm verify` 7 门全过
- [ ] `npm pack --dry-run` 产物结构符合预期（`verify-artifacts` 门已覆盖关键项）

## 3. 避免重复验证反模式

- 声称"构建完成"前，确认跑的是 `pnpm build` 而不是只跑了 vitest（`pnpm test` 的 pretest 虽会自动 build，但直接 `npx vitest` 不会）。
- 发布产物以 `pnpm pack` 到 `install/` 的 tgz 为准，不把 `lib/` 当交付物。

## 4. 相关脚本

| 命令 | 作用 |
|------|------|
| `pnpm build` | tsc -b + 前端 client 构建 → `lib/` |
| `pnpm test` | build（pretest）+ vitest run |
| `pnpm verify` | 7 门：self-contained / artifacts / readme-sync / action-type-producers / spl-block-code / test-cases-coverage / self-protection |
| `pnpm run pack` | npm pack → `install/*.tgz`（prepack 自动过门） |
| `pnpm pack`（不要用） | pnpm 内置命令，绕开上一条，产物落到 cwd |
| `bash scripts/oss-sync.sh "msg" <branch>` | OSS 发版同步（见 §5，分支名必填） |

## 5. OSS 分支维护（github-main，强制）

GitHub 公开仓库（remote `github`，地址 `github.com:zhanxingtai/deepseek-harness-security-control`）走独立孤儿分支 `github-main`，与内网开发分支双轨维护。

### 5.1 红线

- **禁止在 `github-main` 上直接 commit**（含 amend/rebase/cherry-pick）。该分支上的 commit 只允许由 `scripts/oss-sync.sh` 产出。
- OSS commit 身份固定为 `hixss <17995374+hixss@users.noreply.github.com>`，**绝不使用**内网 git 身份（全局 git 配置里的内部邮箱）。
- **绝不执行 `git push --mirror`** 到 `github` remote——会绕过所有防护把内网全量历史（含真实姓名/内部邮箱作者）推到公网。
- 不在 `github` remote 上创建 HTTPS 地址；推送只走 SSH 通道（本机已配置 `ssh.github.com:443` 通路）。

### 5.2 标准发版同步

```bash
bash scripts/oss-sync.sh "release: v1.0.1 说明" <内网分支名>
```

脚本自动完成：squash 内网增量到 `github-main`（noreply 身份）→ 内网分支打 `-s ours` 锚点并推送 origin → 推送 GitHub main。打 tag 需手动：

```bash
git tag -a v1.0.1 -m "release v1.0.1"
git push github v1.0.1
```

若 squash 出现冲突（常见于首次同步或 OSS 分支历史重写后的 add/add），脚本会中止；解决后手动完成剩余步骤（`git checkout --theirs <file>` → `git add` → 带 noreply 身份 `git commit` → 重跑脚本或手动打锚点推送）。

### 5.3 身份兜底

`scripts/git-hooks/pre-commit` 会拒绝在 `github-main` 上使用非 noreply 身份的提交。每个克隆点执行一次启用：

```bash
git config core.hooksPath scripts/git-hooks
```

## 6. 已知事项

- **macOS 软链隐患（已修，2026-10-22）**：此前 `SensitivePathGuard` 对候选路径做 realpath、但 HOME 根用词法形式，导致 HOME 位于软链之后时（macOS `/var` → `/private/var`）symlink 绕过防护匹配失效——指向 `~/.ssh/id_rsa` 的软链能直接溜过去。修复在 `SensitivePathGuard.homeRestVariantsFor`：HOME 侧同时产出词法与 realpath 两个变体。对 deny-list 而言这是 fail-closed 的——多出的变体只会多拦，不会漏放。回归覆盖见 `tests/sensitivePathGuard.test.ts` 的 `symlink-aliasing bypass` 用例。
- **CI 平台差异**：`ci.yml` 单文件承载全部闸口——`linux-package` 在 ubuntu 跑 node 22/24 矩阵，`macos-package` / `windows-package` 各自跑全量 vitest 并产出真实 tgz。测试写临时目录路径断言时，以 `realpathSync.native` 为基准，不要用词法路径（macOS/Windows 上两者可能不同）。另注意两点跨平台陷阱：（1）不要硬编码 `/tmp`，用 `os.tmpdir()`——仓库里 90+ 处调用点都这么做；（2）依赖 `fs.watch` / `statSync().mtimeMs` 轮询的断言不要只靠固定 sleep：Windows runner 与容器文件系统的时间戳粒度会让同一时钟节拍内的两次写入落在同一时间桶（mtimeMs 差值可为 0），条件等待也救不了，必须用 `utimesSync` 显式推进 mtime 再等待。
- 事件落盘为**同步**写入（`src/utils/events/cappedNdjson.ts`），不存在异步排空问题；但自定义 sink 测试若在 afterEach `rmSync` 前不 `shutdown()`，interval 计时器可能重建临时目录（垃圾文件，不致失败）。
