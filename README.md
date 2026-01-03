# acme-cert-worker

[![Deploy Worker](https://github.com/yoogg/acme-cert-worker/actions/workflows/deploy.yml/badge.svg)](https://github.com/yoogg/acme-cert-worker/actions/workflows/deploy.yml)

Cloudflare Worker：自动申请/续期 SSL 证书（DNS-01），并通过 API 输出证书与私钥；支持多 CA 供应商顺序兜底（例如 Let's Encrypt / ZeroSSL / Google Trust Services）。

## 绑定与存储

- 使用 `KV` 绑定 `CERTS_KV`：缓存证书与私钥、以及 ACME account 信息。

## 环境变量（wrangler.toml -> [vars]）

- `ALLOWED_DOMAINS`：允许申请/查询的域名列表（逗号分隔）。支持 `example.com` 与 `*.example.com`。
- `AUTH_TOKEN`：访问 `/cert` 时的 `Authorization: Bearer <token>`。
- `CF_API_TOKEN`：Cloudflare API Token，用于创建/删除 `_acme-challenge` TXT 记录（建议权限：Zone:DNS Edit + Zone:Read）。
- `CF_ZONE_MAP_JSON`：域名 suffix 到 `zoneId` 映射（JSON 数组）。例：`[{"suffix":"example.com","zoneId":"..."}]`。
	- 可选：如果 Token 有 `Zone:Read`，可不填，Worker 会自动查找 zoneId。
	- 如果 Token 没有 `Zone:Read`，则必须填写该映射。
- `RENEW_BEFORE_DAYS`：小于该天数则自动续期（默认 30）。
- `DNS_PROPAGATION_SECONDS`：写入 TXT 记录后等待传播的秒数（默认 20）。
- `CA_PROVIDERS_JSON`：ACME Provider 配置（JSON 数组），按顺序尝试。

## API

- `GET /health`：健康检查
- `GET /cert?domain=example.com`：返回证书（JSON：certPem/notAfter/provider）。
- `GET /key?domain=example.com`：返回私钥（JSON：keyPem/notAfter/provider）。

> 建议：只把 `/key` 暴露在内网或额外加网关保护。

## GitHub 与一键部署

### 1) 发布到 GitHub

在本目录执行：

- `git init`
- `git add .`
- `git commit -m "init"`
- 在 GitHub 新建仓库后：`git remote add origin https://github.com/yoogg/acme-cert-worker.git`
- `git push -u origin main`

### 2) Cloudflare 一键部署（Deploy Button）

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/yoogg/acme-cert-worker)

### 3) GitHub Actions 自动部署（可选）

仓库已内置 GitHub Actions 工作流（见 .github/workflows/deploy.yml）。你需要在 GitHub 仓库设置 Secrets：

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

之后 push 到 `main` 会自动执行 `wrangler deploy`。

### ZeroSSL（可选）

ZeroSSL 通常需要 EAB（External Account Binding）。在 `CA_PROVIDERS_JSON` 中配置：

```json
[
	{
		"provider": "LE",
		"directoryUrl": "https://acme-v02.api.letsencrypt.org/directory"
	},
	{
		"provider": "ZeroSSL",
		"directoryUrl": "https://acme.zerossl.com/v2/DV90",
		"eab": { "kid": "YOUR_KID", "hmacKeyBase64url": "YOUR_HMAC_KEY_BASE64URL" }
	}
]
```

### Google Trust Services（可选）

GTS 的 ACME directory URL 可能随产品/区域不同而变化；建议你把 directory URL 明确写到 `CA_PROVIDERS_JSON` 里作为一个 provider。

## 开发

- `npm i`
- `npm run dev`

## 运行时说明（避免 1101）

本项目依赖的 `@peculiar/x509` 在 Workers 运行时需要 Node 兼容层，因此已在 [wrangler.toml](wrangler.toml) 启用：

- `compatibility_flags = ["nodejs_compat"]`

如果你仍然看到 `Error 1101 Worker threw exception`：

- 打开 Cloudflare Dashboard → Workers → Logs 查看 `console.error` 输出
- 直接访问 `/health` 确认 Worker 是否能正常启动

如果你看到类似 `All ACME providers failed: LE: ACME directory fetch failed: 525`：

- 这通常是网络/上游临时 TLS 握手问题；代码已加入自动重试
- 仍失败时：在 `CA_PROVIDERS_JSON` 增加第二个 provider 作为兜底（例如 ZeroSSL，需配置 EAB）

> 说明：本项目会使用 DNS-01，因此域名的 DNS 需要在 Cloudflare 上可由 Token 管理。
