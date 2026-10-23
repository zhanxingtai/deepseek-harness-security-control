# DeepSeek Harness Security Control - Agent Guidelines

## 1. 构建约定（强制）

### 1.1 包管理器与安装

本项目使用 **pnpm**（CI 经 `pnpm/action-setup@v4` 固定 10.x），Node **22 / 24** 矩阵
（`engines: ^22.19.0 || >=24.0.0`）。

```bash
pnpm install --frozen-lockfile
```

`.npmrc` 的 `auto-install-peers` 必须与 `pnpm-lock.yaml` 的 `settings.autoInstallPeers`
保持一致：`--frozen-lockfile` 会在拉取任何依赖之前就因二者漂移而中止
（`ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`），整条 CI 构建直接失败。锁文件是权威来源。

### 1.2 产物以 tgz 为准，不要拿 `lib/` 当交付物

```bash
pnpm build        # tsc -b + client 构建 → lib/（已 gitignore）
pnpm test         # pretest 会自动先跑 build，再 vitest run
pnpm verify       # 7 个验收门，全过才算可打包
pnpm run pack     # → install/*.tgz（已 gitignore）
```

`pnpm run pack` 与 `pnpm pack` 是两条不同的命令：后者是 pnpm 内置命令，不认
`--pack-destination`，会把 tarball 丢到仓库根目录。打包一律用 `pnpm run pack`。

`prepack` 钩子会自动重跑 prepare + 全部 7 门——手动 `npm pack` 也绕不过验收。

### 1.3 禁止事项

- 不要把 `file:` / 绝对路径依赖加进 package.json（CI 的 `open-source-hygiene` job 会拒）。
- 不要把 `lib/`、`install/*.tgz` 提交进仓库（均已被 gitignore）。
- 不要用裸 `npx vitest` 替代 `pnpm test`——它不触发 pretest 的 build，测的是旧产物。

## 2. 验证清单

改动后必须本地全绿再推送：

- [ ] `pnpm build` 成功
- [ ] `pnpm test` 全绿
- [ ] `pnpm verify` 7 门全过
- [ ] `pnpm run pack` 产出的 `install/*.tgz` 已重新生成

## 3. 避免重复验证反模式

**问题模式**：只跑 `npx vitest`、或只改了 `src/` 却没有重新 build / pack，
导致验证（和部署）仍在用旧构建产物，重复失败。

**正确做法**：

- 每次声称"构建完成"前，确认跑的是 `pnpm build` / `pnpm test`（pretest 会自动 build）。
- 发布与部署以 `pnpm run pack` 产出的 `install/*.tgz` 为准，不把 `lib/` 当交付物。
- 提交前检查 `git status`，确认本次改动对应的产物已重新生成。

## 4. 相关脚本

| 命令 | 作用 | 是否产出 install/*.tgz |
|------|------|------------------------|
| `pnpm build` | tsc -b + client 构建 → `lib/` | ❌ |
| `pnpm test` | build（pretest）+ vitest run | ❌ |
| `pnpm verify` | 7 门：self-contained / artifacts / readme-sync / action-type-producers / spl-block-code / test-cases-coverage / self-protection | ❌ |
| `pnpm run pack` | npm pack → `install/*.tgz`（prepack 自动过门） | ✅ |
| `pnpm pack`（不要用） | pnpm 内置命令，产物落到仓库根 | ⚠️ |

## 5. OSS 分支维护（github-main，强制）

GitHub 公开仓库（remote `github`）走独立孤儿分支 `github-main`，与开发分支双轨维护。

### 5.1 红线

- **禁止在 `github-main` 上直接 commit**（含 amend/rebase/cherry-pick）。该分支上的 commit
  只允许由 `scripts/oss-sync.sh` 产出。
- OSS commit 身份固定为 GitHub noreply，**绝不使用**全局 git 配置里的开发身份。
- **绝不执行 `git push --mirror`** 到 `github` remote——会绕过所有防护把内网全量历史推到公网。
- 不在 `github` remote 上创建 HTTPS 地址；推送只走 SSH 通道。

### 5.2 标准发版同步

```bash
bash scripts/oss-sync.sh "release: v1.0.1 说明" <开发分支名>   # 分支名必填
```

脚本自动完成：squash 开发分支增量到 `github-main`（noreply 身份）→ 开发分支打 `-s ours`
锚点并推送 origin → 推送 GitHub main。打 tag 需手动：

```bash
git tag -a v1.0.1 -m "release v1.0.1"
git push github v1.0.1
```

若 squash 出现冲突（常见于 OSS 分支历史被重写后的 add/add），脚本会中止；解决后手动完成
剩余步骤（`git checkout --theirs <file>` → `git add` → 带 noreply 身份 `git commit` →
重跑脚本或手动打锚点推送）。

### 5.3 身份兜底

`scripts/git-hooks/pre-commit` 会拒绝在 `github-main` 上使用非 noreply 身份的提交。
每个克隆点执行一次启用：

```bash
git config core.hooksPath scripts/git-hooks
```
