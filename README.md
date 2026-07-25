# Edge Proxy Manager

基于 **Cloudflare Workers + KV** 的轻量反向代理管理面板，交互风格参考 [Nginx Proxy Manager](https://nginxproxymanager.com/)。

用一个 Worker 同时提供：

- 管理后台（登录、增删改代理、深色模式）
- 边缘反向代理（HTTPS 访客 → HTTP/HTTPS 源站）

适合把公网域名挂到 Cloudflare，再回源到任意公网 HTTP/HTTPS 服务（含非 80/443 端口）。

## 功能

- 登录会话（8 小时签名 Cookie）
- 代理规则 CRUD，配置存 KV
- 支持 HTTP / HTTPS 回源、自定义端口、WebSocket
- 根路径默认入口（`landingPath` / `landingHash`）
- 自定义 Locations：`/api = http://host:8080`
- 强制 HTTPS、HSTS、常见攻击路径拦截
- 自动改写上游重定向与 Cookie Domain
- 快速粘贴源站 URL 自动拆分字段
- 域名列表可点击新窗口打开 `https://...`
- 设置页绑定 Cloudflare API 令牌，添加代理时选择已托管域名
- 未绑定 API 时禁止添加代理映射
- 证书状态页展示代理域名托管/证书概况
- 管理员可在面板内修改登录密码

## 架构

```text
访客 HTTPS
   │
   ▼
Cloudflare 边缘（Worker）
   │  HTTP 或 HTTPS
   ▼
公网源站（主机名:端口）
```

管理后台只在 `ADMIN_HOSTNAME` 对应域名上提供；其它绑定到该 Worker 的域名走代理逻辑。

## 快速开始

### 1. 准备

- Cloudflare 账号
- 域名 DNS 已接入 Cloudflare
- Node.js 18+

### 2. 安装

```bash
git clone https://github.com/zzusec/edge-proxy-manager.git
cd edge-proxy-manager
npm install
```

### 3. 创建 KV

```bash
npx wrangler kv namespace create PROXY_CONFIG
```

把输出的 id 填进 `wrangler.toml`：

```toml
[[kv_namespaces]]
binding = "PROXY_CONFIG"
id = "你的_KV_ID"
```

### 4. 配置域名

编辑 `wrangler.toml`：

```toml
[vars]
ADMIN_HOSTNAME = "npm.example.com"

[[routes]]
pattern = "npm.example.com"
custom_domain = true
```

代理域名可以在后台添加后，再通过 `[[routes]]` / Custom Domain 绑到同一个 Worker。

### 5. 设置密钥

```bash
npx wrangler secret put ADMIN_USERNAME
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put SESSION_SECRET   # 至少 32 位随机串
```

生成 `SESSION_SECRET`：

```bash
openssl rand -hex 32
```

### 6. 部署

```bash
npm run deploy
```

打开：

```text
https://npm.example.com/login
```

## 添加一条代理

1. 登录管理后台
2. 填写 **代理域名**（如 `api.example.com`）
3. （可选）粘贴完整源站 URL，点「解析填入」
4. 确认协议 / 主机 / 端口 / 入口路径
5. 保存
6. 在 Cloudflare 把该域名绑定到**同一个 Worker**（Custom Domain 或 Route）

### 回源建议

- 优先填 **主机名**，不要填裸 IP（避免源站也在 Cloudflare 时出现 1003）
- 例：`http://origin.example.com:8317/management.html`

## 本地开发

```bash
cp .env.example .dev.vars
# 编辑 .dev.vars
npm run dev
```

## 环境变量

| 名称 | 类型 | 说明 |
|---|---|---|
| `ADMIN_HOSTNAME` | var | 管理后台域名 |
| `ADMIN_USERNAME` | secret | 登录用户名 |
| `ADMIN_PASSWORD` | secret | 登录密码 |
| `SESSION_SECRET` | secret | 会话签名密钥（≥32 字符） |
| `PROXY_CONFIG` | KV binding | 代理配置存储 |

## 目录

```text
.
├── worker.js              # Worker 主程序（管理后台 + 代理）
├── wrangler.toml          # 部署配置（请改成你的域名/KV）
├── wrangler.example.toml  # 示例配置
├── package.json
├── .env.example
└── LICENSE
```

## 安全说明

- 管理后台务必使用独立子域名，并设置强密码
- 不要把真实 `ADMIN_PASSWORD` / `SESSION_SECRET` 提交到仓库
- 代理的是**你自己有权访问**的源站；请遵守目标服务条款与当地法律

## License

[MIT](./LICENSE)
