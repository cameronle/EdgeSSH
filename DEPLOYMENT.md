# EdgeSSH 第一版：部署与验收

## 架构与边界

- 单管理员，无本地用户名、密码、注册、验证码或用户表。身份认证由 Cloudflare Zero Trust Access 完成。
- Access 应用策略只允许管理员的明确邮箱/身份，不能使用 Everyone、Bypass 或允许整个邮箱域的宽泛策略。
- Worker 使用 `jose` 校验 `Cf-Access-Jwt-Assertion` 的 RS256 签名、issuer、audience、有效期、subject 与邮箱。不信任单独的邮箱请求头。所有主机 API、SSH 票据和 WebSocket 附着均需认证。
- D1 中每条主机记录绑定 Access `sub`。AES-256-GCM 加密整个主机资料（包括地址、密码/私钥、指纹和城市），随机 96-bit IV，AAD 绑定账户及记录 ID。
- 密文格式 `v1.<base64 IV>.<base64 ciphertext + tag>`。数据库只明文保存 ID、账户 ID、更新时间。列表响应不包含凭据，连接时才请求解密后的凭据，并仅放在浏览器内存中。
- 当前不是端到端加密：Worker 在 SSH 连接时需要处理明文凭据。具有 Worker 和 Secret 管理权限的人属于信任边界。
- 首次保存/修改地址时，Worker 解析公网 IP，优先向 `https://ipwho.is` 查询城市，被 Cloudflare 共享出口限流或超时时回退至 GeoJS，不发送 SSH 用户名、凭据或命令。定位允许 A/AAAA 单类查询失败并在其他公网地址间回退，位置与实际查询 IP 一同存入加密 payload；前端可随时强制重新定位，失败不阻止保存或连接。
- 前端仍为 Vite + TypeScript，工作台继续复用原 SSH/SFTP/进程实现。地球使用 Mappo 的陆地掩码与 Canvas 球面投影，无 Three.js 等大型依赖；进入工作台后停止地球动画。

## 必需配置

| 名称 | 配置位置 | 含义 |
| --- | --- | --- |
| `DB` | `wrangler.toml` 的 D1 binding | 主机资料数据库，优先复用已有资源 |
| `SSH_SESSIONS` | `wrangler.toml` 的 Durable Object binding | SSH 会话隔离，保留现有类名及迁移历史 |
| `ASSETS` | `wrangler.toml` 的静态资源 binding | 前端构建产物，不需要手动创建 |
| `ACCESS_TEAM_DOMAIN` | Cloudflare Worker Secret | 团队域名，例如 `my-team.cloudflareaccess.com`，不含协议或路径 |
| `ACCESS_AUD` | Cloudflare Worker Secret | 此 Access 应用的 Application Audience (AUD) Tag |
| `ENCRYPTION_KEY` | Cloudflare Worker Secret | 32 字节安全随机数的标准 Base64 |
| `CONNECT_TIMEOUT_MS` | 可选普通变量 | 建连超时；仓库默认 `10000`，通常不要额外配置 |

`DB`、`SSH_SESSIONS` 与 `ASSETS` 是绑定，不是环境变量。生产环境实际需要手动填写的运行时值只有三个 Worker Secret。

## Cloudflare 控制台配置

### 1. 创建 D1 数据库

1. 打开 Cloudflare Dashboard 的 D1 页面；新版界面通常位于 `Storage & databases > D1`，菜单名称可能随控制台更新而变化。
2. 复用本项目已有数据库，或创建一个新的数据库；不要为每次部署重复创建。
3. 将数据库名称和 ID 写入 `wrangler.toml` 的 `[[d1_databases]]`，binding 保持为 `DB`。
4. 数据表不需要在控制台手动建立。GitHub Actions 会执行远程 migration，只添加项目所需 schema，不清空已有数据。

### 2. 配置 Zero Trust Access

1. 进入 `Zero Trust > Access > Applications`，添加一个 `Self-hosted` 应用。
2. 应用域名填写最终访问 EdgeSSH 的自定义域名，并保证该域名与 `wrangler.toml` 的 route 一致。
3. 添加 Allow 策略，只包含管理员的明确邮箱或身份。不要使用 `Everyone`、`Bypass` 或允许整个邮箱域的宽泛规则。
4. 在 Zero Trust 的团队设置中找到 Team Domain，保存不带 `https://` 和路径的域名，例如 `my-team.cloudflareaccess.com`。
5. 在 Access 应用详情中复制 Application Audience (AUD) Tag。不要把应用 ID、Client ID 或策略 ID 当作 AUD。

### 3. 创建部署用 API Token

1. 在 Cloudflare 个人资料的 `API Tokens` 页面创建 Token，选择官方 `Edit Cloudflare Workers` 模板作为起点。
2. 在模板权限之外补充 Account 的 `D1: Edit`，供 workflow 执行远程 migration。
3. 保留模板中的 Worker 与目标 Zone 权限，用于部署脚本及 `custom_domain = true` 的自定义域名；不需要添加 KV、R2 等本项目未使用资源的额外权限。
4. Account Resources 和 Zone Resources 都只选择实际部署所用的账户与域名，不要使用全账户、全站点范围。
5. Token 创建后只会完整显示一次，将它直接保存为 GitHub Actions Secret，不要写进仓库或 Cloudflare Worker 变量。

Cloudflare 账户 ID 可在 Dashboard 的账户概览或 Worker 概览中复制。它不是 Secret，可保存为 GitHub Actions Variable。

### 4. 配置 GitHub Actions

在 GitHub 仓库进入 `Settings > Secrets and variables > Actions`：

| 名称 | GitHub 类型 | 值 |
| --- | --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | Variable | Cloudflare 账户 ID |
| `CLOUDFLARE_API_TOKEN` | Secret | 上一步创建的最小权限 API Token |

进入 `Actions > Deploy > Run workflow` 完成首次部署。workflow 会安装依赖、检查项目、迁移 D1 并创建或更新 Worker。首次运行时尚未配置运行时 Secret，受保护 API 暂时返回 503 属于预期现象。

### 5. 在 Worker 界面添加运行时 Secret

首次部署完成后，进入 `Workers & Pages > edgessh > Settings > Variables and Secrets`，依次添加以下三项，并将类型选择为 **Secret**：

| 名称 | 填写内容 |
| --- | --- |
| `ACCESS_TEAM_DOMAIN` | Zero Trust Team Domain，不带协议和路径 |
| `ACCESS_AUD` | Access 应用详情中的 Application Audience (AUD) Tag |
| `ENCRYPTION_KEY` | 32 字节安全随机数的标准 Base64，只在首次部署时生成 |

保存后按控制台提示部署新版本。不要在 GitHub Actions 中重复保存这三项，也不要为 `DB`、`SSH_SESSIONS` 或 `ASSETS` 创建同名变量。`CONNECT_TIMEOUT_MS` 已由 `wrangler.toml` 设置为 `10000`，只有确实需要调整 2,000 至 30,000 毫秒的建连超时时才在配置中修改。

`ENCRYPTION_KEY` 应由可信的密码管理器或本机安全随机数工具生成，解码后必须正好为 32 字节。不要使用普通密码、UUID、示例值或在线随机字符串网页。密钥丢失将无法解密现有资料；当前版本不支持直接轮换，后续部署必须复用原值。

## 部署顺序

1. 检查 Cloudflare 已有 Worker、D1 与 Access 应用，确认资源属于本项目，避免覆盖其他项目。
2. 配置 D1、Access 与最小权限 API Token，再将两个部署值保存到 GitHub Actions。
3. 手动运行一次 `Deploy` workflow，让 GitHub Actions 自动迁移 D1 并创建或更新 Worker。
4. 在 Worker 的 `Variables and Secrets` 界面添加三个运行时 Secret，保存并部署。
5. 以后只需推送到 `main`；workflow 会复用原有资源和 Secret 自动发布，不需要在本地执行 Wrangler 部署命令。
6. 通过实际 Access 入口验收。所有账号、主机与连接 API 均需 Access 保护；缺少 Access Secret 时会返回 503，不能操作主机或连接 SSH。

密钥丢失将无法解密现有资料。更换密钥必须设计旧密钥解密、新密钥重加密的迁移，不可直接覆盖 Secret。当前版本不提供自动轮换。更换 Access 团队或身份导致 `sub` 改变时，也需要显式的数据迁移。

### GitHub Actions

`.github/workflows/deploy.yml` 在推送到 `main` 或手动触发时依次执行安装、项目检查、远程 D1 迁移与 Worker 部署。生产部署使用并发锁串行执行，避免迁移和 Worker 版本交错。

仓库只需配置两个 Actions 值：

| 名称 | 配置位置 | 要求 |
| --- | --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | Actions Variable | 目标 Cloudflare 账户 ID |
| `CLOUDFLARE_API_TOKEN` | Actions Secret | 限定到目标账户，并具备 Workers 部署与 D1 迁移权限 |

三个运行时 Worker Secret 不进入 GitHub Actions，统一在 Cloudflare Worker 的 `Variables and Secrets` 界面管理；日常自动部署只复用 Cloudflare 中已有值。不要把本地 `.dev.vars` 或 `wrangler secret put` 作为普通用户的生产配置流程。

## 验收清单（5.6 SOL 执行）

- `npm run typecheck`、`npm test`、`npm run build:web`、Wrangler dry-run。
- Access：无 JWT、伪造 JWT、错误签名、错误 audience、错误 issuer、过期令牌均不能访问主机、票据和三种 WebSocket。
- 两个不同 `sub` 的测试身份不能读取、修改、删除或解密彼此主机；DO 票据及辅助通道绑定相同账户。
- 拒绝跨站 Origin；写操作缺少 Origin 也应拒绝；错误不泄露堆栈、凭据或数据库内容。
- D1 新增/修改/删除、刷新后恢复、空密码语义、私钥保存、留空保留凭据、切换认证方式、指纹持久化。
- AES-GCM 随机 IV、错误密钥/账户/主机 ID/篡改密文均不能解密，直接检查 D1 中不存在主机明文和凭据。
- 定位失败不阻塞保存；私人地址不会被拿来发 HTTP 请求；城市标签与实际记录对应。
- 地球点位和列表均可进入工作台；返回总览断开会话；工作台不显示/运行地球；刷新后主机仍存在。
- 空列表、错误态、编辑/删除确认、搜索、分组、键盘操作；截图检查桌面及 320/375/414/768px，无水平溢出。
- 用真实获授权的 SSH 测试目标验收握手、主机指纹、终端、SFTP 与进程面板。若未提供目标凭据，不得声称真实 SSH 验收通过。
- 测试数据只用明确测试身份和测试主机，完成后清除自己创建的测试记录；不得清空生产表。

## 第一版限制

- 每个身份最多 200 台主机；无团队共享、后台密码登录、账号找回或旧浏览器记录自动导入。
- 地球位置不等于在线状态，没有伪造的在线数、延迟和会话历史。
- 同一城市的多个点可能接近，列表为完整可访问入口。
- 首页为中文；原 SSH 工作台保留中英文切换。
- 国旗使用本地 `flag-icons` SVG（MIT，许可证随静态资源部署），在 Windows 上也显示实际旗帜，不依赖 emoji 字体。

## 2026-09-19 线上部署记录

- 正式入口：`https://ssh.865455.xyz`
- D1：`edgessh-accounts`（`f7059f46-a0df-4924-bb8d-de6cf213f6c4`）
- D1 schema：`hosts`、`d1_migrations`；记录数分别为 0、1
- 活动版本：由 Cloudflare Workers Builds 监听 `production` 分支自动发布，当前状态以 Workers Builds 记录与 Cloudflare 控制台为准
- Secret 名称：`ENCRYPTION_KEY`、`ACCESS_TEAM_DOMAIN`、`ACCESS_AUD`；本次部署未读取或覆盖任何运行时 Secret
- 无会话 Smoke：正式入口 `/` 与 `/api/auth/me` 均返回 Access 302，TLS 正常；未记录重定向地址、Team Domain、AUD、JWT、Cookie 或 Secret 值
- `workers.dev` 未作为生产入口启用；账号、主机、凭据与 SSH 等接口均通过 `ssh.865455.xyz` 的 Cloudflare Access 保护
- 待验收：需要用户登录 Access 后验收账号 API，并使用真实授权 SSH 目标验收终端、SFTP 与进程面板

## 自定义域名

- 正式入口：`https://ssh.865455.xyz`
- `workers.dev` 未作为生产入口；Worker 仍在应用层强制校验所有生产账号与连接 API，不允许绕过自定义域名上的 Access 策略。
- Access 应用、策略与三个运行时 Secret 均由用户在 Cloudflare 控制台维护；Cloudflare Workers Builds 负责从 `production` 分支构建与部署代码。
