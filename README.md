# ChatGPT Team 邀请码管理系统

一个简洁的 ChatGPT Team 邀请码分发系统，支持多车位管理、LinuxDO OAuth 登录、自动同步车位状态。

## 功能特性

- 🚗 **多车位管理** - 支持多个 ChatGPT Team 账号，自动同步座位状态
- 🔐 **LinuxDO OAuth** - 使用 LinuxDO 账号登录，无需注册
- 🎫 **邀请码系统** - 生成、分发、追踪邀请码使用情况
- 🤖 **Turnstile 验证** - 可选的 Cloudflare 人机验证
- 🔑 **TOTP 二步验证** - 可选的管理员登录二步验证
- 🌙 **深色模式** - 支持深色/浅色主题切换
- 📊 **后台管理** - 车位管理、邀请码管理、用户管理

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/wukazis/team.git
cd team
```

### 2. 安装依赖

```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. 配置环境变量

```bash
cp .env.example .env
```

编辑 `.env` 文件，配置必要参数：

```env
# 必须配置
ADMIN_PASSWORD=your-secure-password
APP_BASE_URL=https://your-domain.com

# LinuxDO OAuth（必须）
LINUXDO_CLIENT_ID=your-client-id
LINUXDO_CLIENT_SECRET=your-client-secret
LINUXDO_REDIRECT_URI=https://your-domain.com/api/oauth/callback

# 可选配置
ADMIN_TOTP_SECRET=          # TOTP 密钥，留空不启用二步验证
CF_TURNSTILE_SITE_KEY=      # Turnstile site key，留空不启用
CF_TURNSTILE_SECRET_KEY=    # Turnstile secret key
```

### 4. 运行

```bash
python app.py
```

访问 `http://localhost:5000` 查看前台，`http://localhost:5000/admin` 进入管理后台。

## 配置说明

### LinuxDO OAuth

1. 前往 [LinuxDO Connect](https://connect.linux.do/) 创建应用
2. 设置回调地址为 `https://your-domain.com/api/oauth/callback`
3. 获取 Client ID 和 Client Secret

### ChatGPT Team 车位

在管理后台添加车位时需要：

- **Authorization Token**: 从 ChatGPT 网页版获取的 Bearer token
- **Account ID**: Team 账号 ID

获取方法：登录 ChatGPT → 打开开发者工具 → Network → 找到任意 API 请求 → 复制 `authorization` 和 `chatgpt-account-id` 头

### TOTP 二步验证（可选）

1. 生成一个 Base32 密钥（如 `JBSWY3DPEHPK3PXP`）
2. 在 `.env` 中设置 `ADMIN_TOTP_SECRET=你的密钥`
3. 使用 Google Authenticator 等 App 添加该密钥

### Cloudflare Turnstile（可选）

1. 在 [Cloudflare Dashboard](https://dash.cloudflare.com/) 创建 Turnstile widget
2. 获取 Site Key 和 Secret Key
3. 在 `.env` 中配置

## 生产部署

建议使用 Gunicorn + Nginx：

```bash
pip install gunicorn
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

Nginx 配置示例：

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 技术栈

- **后端**: Python Flask
- **数据库**: SQLite (WAL 模式)
- **前端**: 原生 HTML/CSS/JS
- **认证**: JWT + Session

## License

MIT
