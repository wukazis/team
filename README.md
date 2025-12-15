# 简化版邀请码系统

单文件 Flask 应用，支持多车账号管理。

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 复制配置文件
cp .env.example .env

# 编辑 .env 设置管理密码
# ADMIN_PASSWORD=your-password

# 运行
python app.py
```

## 访问

- 用户页面: http://localhost:5000
- 管理后台: http://localhost:5000/admin

## 功能

- 多车账号管理
- 邀请码生成与绑定
- 实时车位状态显示
- Notion 风格管理后台
