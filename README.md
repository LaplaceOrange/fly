# 中国人能飞

一个面向 Debian 单服务器部署的实时起飞状态网站。公开仪表盘展示本站用户的起飞趋势、排行榜、热力图和实时动态；用户通过 [CPOAuth](https://www.cpoauth.com/about) 登录，并在 Cloudflare Turnstile 验证通过后记录一次起飞。

后端是 Go 单二进制，前端为嵌入式 React 静态资源，数据存储在 SQLite WAL 中。不需要 PostgreSQL、Redis 或独立 WebSocket 服务。

## 功能

- CPOAuth Authorization Code + PKCE 登录，按 `sub` 识别用户并同步用户名、显示名和头像。
- 24 小时、7 天、滚动 30 天和全部时间排行榜。
- 全站统计、轻量 SVG 趋势图、Top 10 柱状图、星期/小时热力图和用户状态表。
- WebSocket 实时广播，断线后自动重连并重新同步 REST 快照。
- Cloudflare Turnstile 服务端 Siteverify，校验 hostname、action 和客户端 IP。
- 可配置的滚动限速；同一用户并发提交只会写入一次。
- 带设备 Ed25519 签名的分享卡片，旧版 ECDSA P-256 分享保持只读兼容。
- 指定接收者端到端加密：一次性 X25519 预密钥、HKDF-SHA-256、AES-256-GCM、Ed25519 身份绑定与安全码核验。
- 设备密钥管理与撤销；接收者密钥首次使用或变更时必须明确核对并信任安全码。
- systemd、Caddy、Docker Compose、健康检查和 SQLite 备份说明。

## 配置外部服务

### CPOAuth

1. 在 CPOAuth 创建应用并取得 Client ID、Client Secret。
2. 回调地址必须精确配置为：

   ```text
   https://你的域名/api/auth/callback
   ```

3. 本项目申请 `openid profile`，只使用 `sub`、`username`、`display_name` 和 `avatar_url`。

### Cloudflare Turnstile

1. 在 Cloudflare 创建 Managed Turnstile widget。
2. 域名至少加入生产域名；本地测试可加入 `localhost` 和 `127.0.0.1`。
3. 将 site key 与 secret key 分别写入 `.env`。
4. 前端 action 固定为 `turnstile-spin-v2`，后端会严格校验该值。

Turnstile token 只从浏览器提交到本站后端。Siteverify 始终由后端调用，secret key 不会进入前端构建产物。Cloudflare 的第三方脚本运行在不带 `allow-same-origin` 的沙箱 iframe 中，不能读取主页面 IndexedDB、DOM 或设备私钥。

## 本地运行

要求 Go 1.23+、Node.js 22+。

```bash
cp .env.example .env
# 编辑 .env，填入真实 CPOAuth、Turnstile 和 SESSION_SECRET
npm --prefix web install
npm --prefix web run build
go run .
```

访问 `http://localhost:8080`。

起飞成功弹窗会尝试播放仓库根目录的 `ChineseCanFly.mp3`。构建脚本会自动把该文件复制进前端静态资源；文件不存在或浏览器阻止自动播放时，起飞记录和弹窗仍会正常工作。

前后端分离热更新时，在 `.env` 中把 `PUBLIC_BASE_URL` 临时改成 `http://127.0.0.1:5173`，然后分别运行：

```bash
go run .
npm --prefix web run dev
```

Vite 会把 `/api` 和 WebSocket 请求代理到 `127.0.0.1:8080`。

## `.env`

从 `.env.example` 复制。生产环境至少修改：

- `PUBLIC_BASE_URL`：完整 HTTPS 地址，无尾部路径。
- `CPOAUTH_CLIENT_ID` / `CPOAUTH_CLIENT_SECRET`。
- `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY`。
- `TURNSTILE_EXPECTED_HOSTNAME`：只写 hostname，不含协议和端口。
- `SESSION_SECRET`：至少 32 个随机字符，可用 `openssl rand -base64 48` 生成。
- `TAKEOFF_RATE_LIMIT_MINUTES`：每位用户两次起飞之间的分钟数。
- `SHARE_TTL_HOURS`：签名分享链接的有效小时数，默认 168 小时。
- `TRUSTED_PROXY_CIDRS`：只有这些反向代理可以提供客户端 IP 请求头。

`.env` 已被 Git 忽略。不要提交真实密钥。

## 分享加密与签名

每个浏览器设备在登录后生成长期身份密钥，并维护一组一次性预密钥：

- Ed25519 用于签名分享、长期 X25519 设备公钥和一次性 X25519 预密钥。
- 长期 X25519 公钥用于标识设备；新分享不再直接用长期 X25519 私钥包装内容密钥。
- 一次性 X25519 预密钥用于实际密钥交换。每个预密钥只能被服务器原子领取并消费一次，成功解密后对应私钥从接收设备 IndexedDB 删除；已解密内容由本机不可导出的 AES-GCM 缓存密钥加密保存至分享过期，以便同一设备再次查看。
- 长期私钥和预密钥私钥均以不可导出的 `CryptoKey` 保存在浏览器 IndexedDB；服务器只保存公钥、绑定签名和指纹。
- 每份分享在浏览器签名，服务器写入前验证一次，接收方解密前再次验证。

启用端到端加密时：

1. 分享者选择一名拥有可用一次性 X25519 预密钥的接收用户。
2. 浏览器生成随机 AES-256 内容密钥和临时 X25519 密钥对。
3. 发送端验证长期 X25519 设备公钥及一次性预密钥的两层 Ed25519 绑定签名。
4. 首次向接收者加密，或接收者 Ed25519 设备集合变化时，界面显示安全码并要求通过独立渠道核对后明确确认；确认结果以 TOFU 记录保存在本机。
5. 针对接收者每台有可用预密钥的设备执行临时 X25519 × 一次性 X25519，并用 HKDF-SHA-256 派生独立包装密钥。
6. 内容使用 AES-256-GCM 加密，内容密钥再由每台设备的包装密钥通过 AES-256-GCM 加密。
7. Ed25519 v3 分享签名覆盖签名版本、发送者 CPOAuth `sub`、密文、接收者 ID、临时公钥、全部密钥信封和过期时间。
8. 服务器在同一事务内消费领取的一次性预密钥并写入分享；领取凭据不能重放。
9. 服务器只保存密文、签名、临时公钥和包装后的密钥。

发送界面会列出接收设备指纹和安全码；打开分享时也会对分享者 Ed25519 签名密钥执行独立 TOFU 核对。首次使用必须人工确认，之后密钥变化会阻止加密、解密或展示载荷，直到用户重新核对并确认。账户菜单中的“设备密钥”可列出并撤销丢失设备；撤销会停止该设备创建或接收新分享，但不破坏历史分享的签名验证。

新版链接不在 URL 中携带 AES 密钥。历史 `#key=` 和 v2 静态 X25519 分享仍可打开，但不会再创建。现代加密分享要求 HTTPS 或 localhost，并要求浏览器支持 Web Crypto Ed25519、X25519、AES-GCM、HKDF 和 IndexedDB；Web Locks 不可用时使用短期跨标签页租约避免重复生成密钥。

### 威胁模型边界

此实现保护分享内容免受被动数据库读取、日志泄露、网络窃听和存储服务器读取。服务器拿不到 AES 内容密钥或浏览器私钥；一次性预密钥私钥在成功解密后删除，因此以后泄露长期 X25519 私钥不会解开已经消费的一次性预密钥分享。

浏览器仍从本站下载应用 JavaScript。若站点服务器在某次访问中主动投递恶意前端代码，该代码运行在主页面权限内，能够在用户操作时读取明文或调用不可导出的 `CryptoKey`。抵抗这类主动服务器需要独立分发并固定校验的客户端（例如签名桌面应用或浏览器扩展），不是普通 Web 部署可以单独保证的属性。Cloudflare Turnstile 已隔离到无同源权限的沙箱 iframe，第三方验证脚本不能访问主页面私钥。

起飞记录、排行榜和公开用户资料本身不做端到端加密，否则服务器无法进行全站统计。只有分享载荷使用该选项。

## Debian + systemd 部署

构建：

```bash
make build
sudo useradd --system --home /var/lib/chinese-can-fly --shell /usr/sbin/nologin chinese-can-fly
sudo install -d -o chinese-can-fly -g chinese-can-fly -m 0750 /opt/chinese-can-fly /var/lib/chinese-can-fly
sudo install -m 0755 bin/chinese-can-fly /opt/chinese-can-fly/chinese-can-fly
sudo install -m 0600 .env /etc/chinese-can-fly.env
sudo install -m 0644 deploy/chinese-can-fly.service /etc/systemd/system/chinese-can-fly.service
sudo systemctl daemon-reload
sudo systemctl enable --now chinese-can-fly
```

生产 `.env` 建议设置：

```dotenv
LISTEN_ADDR=127.0.0.1:8080
DATABASE_PATH=/var/lib/chinese-can-fly/fly.db
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
```

安装 Caddy 后，把 `deploy/Caddyfile` 中的域名改为实际域名并复制到 `/etc/caddy/Caddyfile`。Caddy 会自动代理 WebSocket 和申请 HTTPS 证书。

## Docker Compose

在 `.env` 中额外设置 `DOMAIN` 和正确的 `PUBLIC_BASE_URL`：

```dotenv
DOMAIN=fly.example.com
PUBLIC_BASE_URL=https://fly.example.com
```

然后运行：

```bash
docker compose up -d --build
```

项目默认使用腾讯 npm 镜像。如果还需要国内 Go 镜像，可在 `.env` 中覆盖：

```dotenv
NPM_REGISTRY=https://mirrors.cloud.tencent.com/npm/
GOPROXY=https://goproxy.cn,direct
```

## 测试

```bash
go test ./...
go test -race ./...
npm --prefix web test
npm --prefix web run build
```

测试覆盖并发限速、会话、OAuth、Turnstile、WebSocket 广播、分享持久化、Ed25519 签名、X25519/HKDF/AES-GCM 往返加解密、接收者访问控制和前端图表组件。

## 数据备份

SQLite 数据库默认位于 `./data/fly.db`。服务运行时使用 SQLite 在线备份：

```bash
sqlite3 /var/lib/chinese-can-fly/fly.db ".backup '/path/to/backup/fly-$(date +%F-%H%M).db'"
```

不要只复制主 `.db` 文件而忽略正在使用的 WAL。恢复前先停止服务，并同时保留一份原数据库副本。

## 开源许可证

本项目采用 [Apache License 2.0](./LICENSE)，版权所有 © 2026 FSY / LaplaceOrange。
