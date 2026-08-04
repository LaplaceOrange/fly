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
- 带设备 ECDSA P-256 签名的分享卡片。
- 分享时可选 AES-256-GCM 端到端加密：服务器只保存密文，密钥只放在 URL `#fragment` 中。
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

Turnstile token 只从浏览器提交到本站后端。Siteverify 始终由后端调用，secret key 不会进入前端构建产物。

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

每个浏览器设备首次分享时会生成 ECDSA P-256 密钥对：

- 非导出的私钥保存在该浏览器的 IndexedDB 中。
- 公钥绑定当前 CPOAuth 用户并保存在服务器。
- 每份分享在浏览器签名，服务器写入前验证一次，接收方打开页面后再次验证。

启用端到端加密时：

1. 浏览器为该分享生成随机 256 位 AES 密钥和 96 位 IV。
2. 分享寄语和统计快照使用 AES-GCM 加密。
3. 服务器保存密文、IV、签名和公钥，不保存 AES 密钥。
4. AES 密钥放在 `https://域名/share/ID#key=...` 的 fragment 中；浏览器不会把 fragment 发送给 HTTP 服务器。

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

测试覆盖并发限速、会话、OAuth、Turnstile、WebSocket 广播、分享持久化、ECDSA 签名验证和前端图表组件。

## 数据备份

SQLite 数据库默认位于 `./data/fly.db`。服务运行时使用 SQLite 在线备份：

```bash
sqlite3 /var/lib/chinese-can-fly/fly.db ".backup '/path/to/backup/fly-$(date +%F-%H%M).db'"
```

不要只复制主 `.db` 文件而忽略正在使用的 WAL。恢复前先停止服务，并同时保留一份原数据库副本。
