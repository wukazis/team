#!/usr/bin/env python3

import os
import secrets
import threading
import time
import hmac
import struct
import hashlib
import base64
import jwt
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlencode
from flask import Flask, request, jsonify, send_from_directory, session, redirect
from dotenv import load_dotenv
import requests
from contextlib import contextmanager

load_dotenv()

# 数据库配置
DATABASE_URL = os.environ.get('DATABASE_URL', '')
DB_PATH = os.environ.get('DB_PATH', 'data.db')

# 判断使用哪种数据库
USE_POSTGRES = DATABASE_URL.startswith('postgresql')

if USE_POSTGRES:
    import psycopg2
    from psycopg2 import pool
    from psycopg2.extras import RealDictCursor
    # PostgreSQL 连接池
    db_pool = None
else:
    import sqlite3

# 同步间隔（秒）
SYNC_INTERVAL = int(os.environ.get('SYNC_INTERVAL', 30))

# LinuxDO OAuth 配置
LINUXDO_CLIENT_ID = os.environ.get('LINUXDO_CLIENT_ID', '')
LINUXDO_CLIENT_SECRET = os.environ.get('LINUXDO_CLIENT_SECRET', '')
LINUXDO_REDIRECT_URI = os.environ.get('LINUXDO_REDIRECT_URI', 'http://localhost:5000/api/oauth/callback')
LINUXDO_AUTHORIZE_URL = 'https://connect.linux.do/oauth2/authorize'
LINUXDO_TOKEN_URL = 'https://connect.linux.do/oauth2/token'
LINUXDO_USERINFO_URL = 'https://connect.linux.do/api/user'

# Cloudflare Turnstile 配置
CF_TURNSTILE_SITE_KEY = os.environ.get('CF_TURNSTILE_SITE_KEY', '')
CF_TURNSTILE_SECRET_KEY = os.environ.get('CF_TURNSTILE_SECRET_KEY', '')

# Microsoft Graph API 邮件配置
MS_TENANT_ID = os.environ.get('MS_TENANT_ID', '')
MS_CLIENT_ID = os.environ.get('MS_CLIENT_ID', '')
MS_CLIENT_SECRET = os.environ.get('MS_CLIENT_SECRET', '')
MS_MAIL_FROM = os.environ.get('MS_MAIL_FROM', '')  # 发件人邮箱

# 测试模式（跳过真实发送 ChatGPT 邀请）
TEST_MODE = os.environ.get('TEST_MODE', 'false').lower() == 'true'

# 发车模式：auto=自动发车, manual=手动确认发车
DISPATCH_MODE = os.environ.get('DISPATCH_MODE', 'auto')  # 默认自动模式

# 候车室设置（从数据库加载，默认关闭）
WAITING_ROOM_ENABLED = False  # 候车室是否开放（默认关闭）
WAITING_ROOM_MAX_QUEUE = 0    # 排队人数上限，0表示不限制

# JWT 配置
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_EXPIRY_HOURS = 24

# OAuth state 存储
oauth_states = {}

# API 限流配置
rate_limit_store = {}  # {ip: {endpoint: [(timestamp, count)]}}
RATE_LIMITS = {
    'default': (60, 60),      # 默认：60秒内60次
    'oauth': (60, 10),        # OAuth：60秒内10次
    'invite': (60, 5),        # 邀请码：60秒内5次
    'admin_login': (60, 5),   # 管理员登录：60秒内5次
    'queue_join': (60, 3),    # 排队：60秒内3次（防止疯狂点击）
}

# 全局限流（针对高并发场景）
global_rate_limit = {'queue_join': [], 'lock': threading.Lock()}
GLOBAL_RATE_LIMITS = {
    'queue_join': (1, 50),    # 每秒最多处理50个排队请求
}

def get_client_ip():
    """获取客户端真实IP"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

def check_rate_limit(limit_type='default'):
    """检查请求是否超过限流"""
    ip = get_client_ip()
    now = time.time()
    window, max_requests = RATE_LIMITS.get(limit_type, RATE_LIMITS['default'])
    
    if ip not in rate_limit_store:
        rate_limit_store[ip] = {}
    if limit_type not in rate_limit_store[ip]:
        rate_limit_store[ip][limit_type] = []
    
    # 清理过期记录
    rate_limit_store[ip][limit_type] = [t for t in rate_limit_store[ip][limit_type] if now - t < window]
    
    if len(rate_limit_store[ip][limit_type]) >= max_requests:
        return False
    
    rate_limit_store[ip][limit_type].append(now)
    return True

def check_global_rate_limit(limit_type):
    """检查全局限流（所有用户共享）"""
    if limit_type not in GLOBAL_RATE_LIMITS:
        return True
    
    window, max_requests = GLOBAL_RATE_LIMITS[limit_type]
    now = time.time()
    
    with global_rate_limit['lock']:
        if limit_type not in global_rate_limit:
            global_rate_limit[limit_type] = []
        # 清理过期记录
        global_rate_limit[limit_type] = [t for t in global_rate_limit[limit_type] if now - t < window]
        
        if len(global_rate_limit[limit_type]) >= max_requests:
            return False
        
        global_rate_limit[limit_type].append(now)
        return True

def rate_limit(limit_type='default'):
    """限流装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 先检查全局限流
            if not check_global_rate_limit(limit_type):
                return jsonify({'error': '系统繁忙，请稍后再试'}), 503
            # 再检查单用户限流
            if not check_rate_limit(limit_type):
                return jsonify({'error': '请求过于频繁，请稍后再试'}), 429
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 获取当前脚本所在目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path='')

# ========== 管理员操作日志 ==========

def log_admin_action(action, details=None):
    """记录管理员操作日志"""
    try:
        ip = get_client_ip()
        conn = get_db()
        conn.execute(
            'INSERT INTO admin_logs (action, details, ip_address) VALUES (?, ?, ?)',
            (action, details, ip)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"记录管理员日志失败: {e}")

# ========== ChatGPT Team API ==========

def build_chatgpt_headers(account_id: str, auth_token: str) -> dict:
    """构建 ChatGPT API 请求头"""
    token = auth_token if auth_token.startswith("Bearer") else f"Bearer {auth_token}"
    return {
        "accept": "*/*",
        "accept-language": "zh-CN,zh;q=0.9",
        "authorization": token,
        "chatgpt-account-id": account_id,
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    }

def sync_single_account(db_account_id: int, auth_token: str, chatgpt_account_id: str):
    """同步单个车账号状态到数据库"""
    data = fetch_team_status(chatgpt_account_id, auth_token)
    conn = get_db()
    conn.execute('''
        UPDATE team_accounts SET seats_in_use = ?, seats_entitled = ?, pending_invites = ?, active_until = ?, last_sync = datetime('now')
        WHERE id = ?
    ''', (data['seats_in_use'], data['seats_entitled'], data['pending_invites'], data.get('active_until'), db_account_id))
    conn.commit()
    conn.close()
    return data

def fetch_team_status(account_id: str, auth_token: str) -> dict:
    """获取 ChatGPT Team 状态"""
    headers = build_chatgpt_headers(account_id, auth_token)
    
    # 获取订阅信息
    subs_url = f"https://chatgpt.com/backend-api/subscriptions?account_id={account_id}"
    subs_resp = requests.get(subs_url, headers=headers, timeout=15)
    subs_resp.raise_for_status()
    subs_data = subs_resp.json()
    
    # 获取待处理邀请数
    invites_url = f"https://chatgpt.com/backend-api/accounts/{account_id}/invites?offset=0&limit=1&query="
    invites_resp = requests.get(invites_url, headers=headers, timeout=15)
    invites_resp.raise_for_status()
    invites_data = invites_resp.json()
    
    return {
        "seats_in_use": subs_data.get("seats_in_use", 0),
        "seats_entitled": subs_data.get("seats_entitled", 0),
        "pending_invites": invites_data.get("total", 0),
        "plan_type": subs_data.get("plan_type"),
        "will_renew": subs_data.get("will_renew"),
        "active_until": subs_data.get("active_until"),
    }

def send_team_invite(account_id: str, auth_token: str, email: str) -> dict:
    """发送 ChatGPT Team 邀请"""
    token = auth_token if auth_token.startswith("Bearer") else f"Bearer {auth_token}"
    headers = {
        "accept": "*/*",
        "authorization": token,
        "chatgpt-account-id": account_id,
        "content-type": "application/json",
        "origin": "https://chatgpt.com",
        "referer": "https://chatgpt.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    }
    
    url = f"https://chatgpt.com/backend-api/accounts/{account_id}/invites"
    payload = {"email_addresses": [email], "role": "standard-user", "resend_emails": True}
    
    resp = requests.post(url, headers=headers, json=payload, timeout=15)
    return {"status": resp.status_code, "ok": resp.status_code == 200, "body": resp.text}
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DB_PATH = os.environ.get('DB_PATH', 'data.db')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')
ADMIN_TOTP_SECRET = os.environ.get('ADMIN_TOTP_SECRET', '')
APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://localhost:5000')

# ========== JWT 工具 ==========

def create_jwt_token(user_id, username):
    """创建 JWT token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token):
    """验证 JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def jwt_required(f):
    """JWT 认证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': '请先登录'}), 401
        token = auth_header[7:]
        payload = verify_jwt_token(token)
        if not payload:
            return jsonify({'error': '登录已过期，请重新登录'}), 401
        request.user = payload
        return f(*args, **kwargs)
    return decorated

# ========== Turnstile 验证 ==========

def verify_turnstile(token, ip=None):
    """验证 Cloudflare Turnstile"""
    if not CF_TURNSTILE_SECRET_KEY:
        return True  # 未配置则跳过验证
    
    data = {
        'secret': CF_TURNSTILE_SECRET_KEY,
        'response': token
    }
    if ip:
        data['remoteip'] = ip
    
    try:
        resp = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=data, timeout=5)
        result = resp.json()
        return result.get('success', False)
    except:
        return False

def init_db_pool():
    """初始化 PostgreSQL 连接池"""
    global db_pool
    if USE_POSTGRES and db_pool is None:
        db_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=5,
            maxconn=50,
            dsn=DATABASE_URL
        )
        print("PostgreSQL 连接池已初始化")

class DictRowWrapper:
    """包装 PostgreSQL 返回的字典，支持数字索引和键名访问"""
    def __init__(self, row):
        self._row = dict(row) if row else {}
        self._keys = list(self._row.keys()) if self._row else []
    
    def __getitem__(self, key):
        if isinstance(key, int):
            # 数字索引访问
            return self._row[self._keys[key]]
        # 键名访问
        return self._row[key]
    
    def __iter__(self):
        return iter(self._keys)
    
    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, IndexError):
            return default
    
    def keys(self):
        return self._keys
    
    def values(self):
        return self._row.values()
    
    def items(self):
        return self._row.items()

class PostgresConnectionWrapper:
    """PostgreSQL 连接包装器，模拟 SQLite 的接口"""
    def __init__(self, conn):
        self._conn = conn
        self._cursor = None
        self._lastrowid = None
    
    def _convert_sql(self, sql):
        """转换 SQLite SQL 到 PostgreSQL"""
        import re
        # 转换占位符
        sql = sql.replace('?', '%s')
        # 转换时间函数
        sql = sql.replace("datetime('now')", "NOW()")
        # 处理 SQLite 的时间计算语法 '+N seconds'
        sql = re.sub(r"'\+(\d+) seconds'", r"|| INTERVAL '\1 seconds'", sql)
        sql = re.sub(r", '\+(\d+) seconds'\)", r" + INTERVAL '\1 seconds')", sql)
        # INSERT OR IGNORE -> INSERT ... ON CONFLICT DO NOTHING
        if 'INSERT OR IGNORE' in sql.upper():
            sql = sql.replace('INSERT OR IGNORE', 'INSERT')
            sql = sql.rstrip(')') + ') ON CONFLICT DO NOTHING'
        # INSERT OR REPLACE -> INSERT ... ON CONFLICT DO UPDATE (需要知道主键)
        if 'INSERT OR REPLACE' in sql.upper():
            sql = sql.replace('INSERT OR REPLACE', 'INSERT')
            if 'system_settings' in sql:
                sql = sql.rstrip(')') + ') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value'
        return sql
    
    def execute(self, sql, params=None):
        sql = self._convert_sql(sql)
        self._cursor = self._conn.cursor(cursor_factory=RealDictCursor)
        try:
            if params:
                self._cursor.execute(sql, params)
            else:
                self._cursor.execute(sql)
        except Exception as e:
            self._conn.rollback()
            raise e
        return self
    
    def executescript(self, sql):
        # PostgreSQL 不支持 executescript，逐条执行
        cursor = self._conn.cursor()
        for statement in sql.split(';'):
            statement = statement.strip()
            if statement:
                try:
                    cursor.execute(self._convert_sql(statement))
                except Exception as e:
                    print(f"SQL 执行失败: {statement[:100]}... 错误: {e}")
        return self
    
    def fetchone(self):
        if self._cursor:
            row = self._cursor.fetchone()
            if row is None:
                return None
            # 包装成支持数字索引和键名访问的对象
            return DictRowWrapper(row)
        return None
    
    def fetchall(self):
        if self._cursor:
            rows = self._cursor.fetchall()
            return [DictRowWrapper(row) for row in rows]
        return []
    
    def commit(self):
        self._conn.commit()
    
    def rollback(self):
        self._conn.rollback()
    
    def close(self):
        db_pool.putconn(self._conn)
    
    @property
    def rowcount(self):
        if self._cursor:
            return self._cursor.rowcount
        return 0
    
    @property
    def lastrowid(self):
        return self._lastrowid

def get_db():
    """获取数据库连接"""
    if USE_POSTGRES:
        conn = db_pool.getconn()
        return PostgresConnectionWrapper(conn)
    else:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA cache_size=10000')
        conn.execute('PRAGMA temp_store=MEMORY')
        return conn

def init_db():
    """初始化数据库表结构"""
    if USE_POSTGRES:
        init_db_pool()
        # 直接从连接池获取原始连接用于初始化
        raw_conn = db_pool.getconn()
        cursor = raw_conn.cursor()
        
        # PostgreSQL 建表语句
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS team_accounts (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                authorization_token TEXT,
                account_id TEXT,
                max_seats INTEGER DEFAULT 5,
                seats_entitled INTEGER DEFAULT 5,
                seats_in_use INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1,
                active_until TEXT,
                pending_invites INTEGER DEFAULT 0,
                last_sync TIMESTAMP,
                created_at TIMESTAMP DEFAULT NOW()
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS invite_codes (
                id SERIAL PRIMARY KEY,
                code TEXT UNIQUE NOT NULL,
                team_account_id INTEGER REFERENCES team_accounts(id),
                user_id INTEGER,
                used INTEGER DEFAULT 0,
                used_email TEXT,
                auto_generated INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT NOW(),
                used_at TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                name TEXT,
                avatar_template TEXT,
                trust_level INTEGER DEFAULT 0,
                has_used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS waiting_queue (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) UNIQUE,
                email TEXT,
                notified INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT NOW(),
                notified_at TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_logs (
                id SERIAL PRIMARY KEY,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        ''')
        
        # 创建索引
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_invite_codes_used ON invite_codes(used)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_invite_codes_team_used ON invite_codes(team_account_id, used)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_invite_codes_auto ON invite_codes(auto_generated, used)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_waiting_queue_notified ON waiting_queue(notified)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_has_used ON users(has_used)')
        
        # 初始化默认设置
        cursor.execute("INSERT INTO system_settings (key, value) VALUES ('waiting_room_enabled', 'false') ON CONFLICT (key) DO NOTHING")
        cursor.execute("INSERT INTO system_settings (key, value) VALUES ('waiting_room_max_queue', '0') ON CONFLICT (key) DO NOTHING")
        cursor.execute("INSERT INTO system_settings (key, value) VALUES ('dispatch_mode', 'auto') ON CONFLICT (key) DO NOTHING")
        cursor.execute("INSERT INTO system_settings (key, value) VALUES ('sync_interval', '30') ON CONFLICT (key) DO NOTHING")
        
        raw_conn.commit()
        db_pool.putconn(raw_conn)
        print("PostgreSQL 数据库初始化完成")
    else:
        # SQLite 初始化
        conn = get_db()
        conn.execute('PRAGMA journal_mode=WAL')
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS team_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                authorization_token TEXT,
                account_id TEXT,
                max_seats INTEGER DEFAULT 5,
                seats_entitled INTEGER DEFAULT 5,
                seats_in_use INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1,
                active_until TEXT,
                last_sync TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );
            
            CREATE TABLE IF NOT EXISTS invite_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                team_account_id INTEGER REFERENCES team_accounts(id),
                user_id INTEGER,
                used INTEGER DEFAULT 0,
                used_email TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                used_at TEXT
            );
            
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                name TEXT,
                avatar_template TEXT,
                trust_level INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
        ''')
        # 添加列（如果不存在）
        for sql in [
            'ALTER TABLE team_accounts ADD COLUMN active_until TEXT',
            'ALTER TABLE team_accounts ADD COLUMN pending_invites INTEGER DEFAULT 0',
            'ALTER TABLE users ADD COLUMN has_used INTEGER DEFAULT 0',
            'ALTER TABLE invite_codes ADD COLUMN auto_generated INTEGER DEFAULT 0',
        ]:
            try:
                conn.execute(sql)
            except sqlite3.OperationalError:
                pass
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS waiting_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                email TEXT,
                notified INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                notified_at TEXT
            )
        ''')
        try:
            conn.execute('ALTER TABLE waiting_queue ADD COLUMN user_id INTEGER REFERENCES users(id)')
        except sqlite3.OperationalError:
            pass
        conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_waiting_queue_user_id ON waiting_queue(user_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_invite_codes_used ON invite_codes(used)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_invite_codes_team_used ON invite_codes(team_account_id, used)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_invite_codes_auto ON invite_codes(auto_generated, used)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_waiting_queue_notified ON waiting_queue(notified)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_users_has_used ON users(has_used)')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )
        ''')
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('waiting_room_enabled', 'false')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('waiting_room_max_queue', '0')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('dispatch_mode', 'auto')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('sync_interval', '30')")
        
        conn.commit()
        conn.close()
        print("SQLite 数据库初始化完成")
    
    # 加载设置到全局变量
    load_settings()

def load_settings():
    """从数据库加载设置到全局变量"""
    global WAITING_ROOM_ENABLED, WAITING_ROOM_MAX_QUEUE, DISPATCH_MODE, SYNC_INTERVAL
    try:
        conn = get_db()
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("SELECT value FROM system_settings WHERE key = 'waiting_room_enabled'")
            row = cursor.fetchone()
            if row:
                WAITING_ROOM_ENABLED = row['value'] == 'true'
            
            cursor.execute("SELECT value FROM system_settings WHERE key = 'waiting_room_max_queue'")
            row = cursor.fetchone()
            if row:
                WAITING_ROOM_MAX_QUEUE = int(row['value'])
            
            cursor.execute("SELECT value FROM system_settings WHERE key = 'dispatch_mode'")
            row = cursor.fetchone()
            if row:
                DISPATCH_MODE = row['value']
            
            cursor.execute("SELECT value FROM system_settings WHERE key = 'sync_interval'")
            row = cursor.fetchone()
            if row:
                SYNC_INTERVAL = int(row['value'])
        else:
            row = conn.execute("SELECT value FROM system_settings WHERE key = 'waiting_room_enabled'").fetchone()
            if row:
                WAITING_ROOM_ENABLED = row['value'] == 'true'
            
            row = conn.execute("SELECT value FROM system_settings WHERE key = 'waiting_room_max_queue'").fetchone()
            if row:
                WAITING_ROOM_MAX_QUEUE = int(row['value'])
            
            row = conn.execute("SELECT value FROM system_settings WHERE key = 'dispatch_mode'").fetchone()
            if row:
                DISPATCH_MODE = row['value']
            
            row = conn.execute("SELECT value FROM system_settings WHERE key = 'sync_interval'").fetchone()
            if row:
                SYNC_INTERVAL = int(row['value'])
        
        close_db(conn)
    except Exception as e:
        print(f"加载设置失败: {e}")

def save_setting(key: str, value: str):
    """保存设置到数据库"""
    conn = get_db()
    if USE_POSTGRES:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO system_settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value', (key, value))
    else:
        conn.execute('INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    close_db(conn)

def generate_code():
    return secrets.token_urlsafe(8).upper()[:12]

def parse_datetime(value):
    """解析数据库返回的时间值，兼容 PostgreSQL datetime 对象和 SQLite 字符串"""
    if value is None:
        return None
    if isinstance(value, datetime):
        # PostgreSQL 返回的是 datetime 对象
        return value.replace(tzinfo=None)
    if isinstance(value, str):
        # SQLite 返回的是字符串
        return datetime.fromisoformat(value.replace('Z', '+00:00').replace(' ', 'T')).replace(tzinfo=None)
    return None

# ========== Microsoft Graph API 邮件 ==========

def get_ms_access_token() -> str:
    """获取 Microsoft Graph API 访问令牌"""
    url = f"https://login.microsoftonline.com/{MS_TENANT_ID}/oauth2/v2.0/token"
    data = {
        'client_id': MS_CLIENT_ID,
        'client_secret': MS_CLIENT_SECRET,
        'scope': 'https://graph.microsoft.com/.default',
        'grant_type': 'client_credentials'
    }
    resp = requests.post(url, data=data, timeout=10)
    resp.raise_for_status()
    return resp.json()['access_token']

def send_email(to_email: str, subject: str, html_content: str) -> bool:
    """通过 Microsoft Graph API 发送邮件"""
    if not MS_TENANT_ID or not MS_CLIENT_ID or not MS_CLIENT_SECRET or not MS_MAIL_FROM:
        print("Microsoft Graph API 未配置")
        return False
    
    try:
        token = get_ms_access_token()
        url = f"https://graph.microsoft.com/v1.0/users/{MS_MAIL_FROM}/sendMail"
        
        payload = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "HTML",
                    "content": html_content
                },
                "toRecipients": [
                    {"emailAddress": {"address": to_email}}
                ]
            },
            "saveToSentItems": "false"
        }
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        
        if resp.status_code == 202:
            return True
        else:
            print(f"发送邮件失败: {resp.status_code} {resp.text}")
            return False
    except Exception as e:
        print(f"发送邮件失败: {e}")
        return False

def send_invite_code_email(to_email: str, invite_code: str, team_name: str) -> bool:
    """发送带邀请码的邮件"""
    subject = '您的 Team 邀请码'
    html_content = f'''
    <div style="font-family: system-ui, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #2563eb;">🎉 Team 上车</h2>
        <p>您好！</p>
        <p>您在候车室排队等待的车位现已空出，这是您的专属邀请码：</p>
        <div style="background: #f0f9ff; border: 2px dashed #2563eb; border-radius: 12px; padding: 20px; text-align: center; margin: 20px 0;">
            <p style="color: #64748b; font-size: 14px; margin: 0 0 8px 0;">邀请码</p>
            <p style="font-size: 28px; font-weight: bold; color: #2563eb; letter-spacing: 3px; margin: 0;">{invite_code}</p>
            <p style="color: #64748b; font-size: 13px; margin: 12px 0 0 0;">绑定车位: {team_name}</p>
        </div>
        <p>请前往首页填写邀请码和您的上车邮箱完成领取：</p>
        <p><a href="{APP_BASE_URL}" style="display: inline-block; background: #2563eb; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none;">立即上车</a></p>
        <p style="color: #dc2626; font-size: 14px; margin-top: 20px;">⚠️ 此邀请码仅限您本人使用，请勿分享给他人。</p>
        <p style="color: #64748b; font-size: 13px;">邀请码有效期为邮件发出后的半小时，逾期未用将自动作废。</p>
    </div>
    '''
    return send_email(to_email, subject, html_content)

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return jsonify({'error': '需要管理员权限'}), 401
        return f(*args, **kwargs)
    return decorated

# ========== 页面路由 ==========

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/admin')
def admin_page():
    return send_from_directory('static', 'admin.html')

@app.route('/waiting')
def waiting_page():
    return send_from_directory('static', 'waiting.html')

# ========== OAuth API ==========

@app.route('/api/oauth/login')
@rate_limit('oauth')
def oauth_login():
    """发起 LinuxDO OAuth 登录"""
    if not LINUXDO_CLIENT_ID:
        return jsonify({'error': 'OAuth 未配置'}), 500
    
    state = secrets.token_urlsafe(32)
    oauth_states[state] = time.time() + 600  # 10分钟过期
    
    params = {
        'client_id': LINUXDO_CLIENT_ID,
        'redirect_uri': LINUXDO_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'read',
        'state': state
    }
    auth_url = f"{LINUXDO_AUTHORIZE_URL}?{urlencode(params)}"
    return jsonify({'authUrl': auth_url, 'state': state})

@app.route('/api/oauth/callback')
def oauth_callback():
    """OAuth 回调"""
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code or not state:
        return redirect(f'{APP_BASE_URL}?error=missing_params')
    
    # 验证 state
    expiry = oauth_states.pop(state, None)
    if not expiry or time.time() > expiry:
        return redirect(f'{APP_BASE_URL}?error=invalid_state')
    
    # 交换 token
    try:
        token_resp = requests.post(LINUXDO_TOKEN_URL, data={
            'client_id': LINUXDO_CLIENT_ID,
            'client_secret': LINUXDO_CLIENT_SECRET,
            'redirect_uri': LINUXDO_REDIRECT_URI,
            'grant_type': 'authorization_code',
            'code': code
        }, timeout=10)
        token_resp.raise_for_status()
        token_data = token_resp.json()
        access_token = token_data.get('access_token')
    except Exception as e:
        print(f"Token exchange failed: {e}")
        return redirect(f'{APP_BASE_URL}?error=token_failed')
    
    # 获取用户信息
    try:
        user_resp = requests.get(LINUXDO_USERINFO_URL, headers={
            'Authorization': f'Bearer {access_token}'
        }, timeout=10)
        user_resp.raise_for_status()
        user_data = user_resp.json()
    except Exception as e:
        print(f"User info fetch failed: {e}")
        return redirect(f'{APP_BASE_URL}?error=userinfo_failed')
    
    # 保存/更新用户
    user_id = user_data.get('id')
    username = user_data.get('username', '')
    name = user_data.get('name', '')
    avatar_template = user_data.get('avatar_template', '')
    trust_level = user_data.get('trust_level', 0)
    
    conn = get_db()
    try:
        existing = conn.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()
        if existing:
            conn.execute('''
                UPDATE users SET username = ?, name = ?, avatar_template = ?, trust_level = ?, updated_at = datetime('now')
                WHERE id = ?
            ''', (username, name, avatar_template, trust_level, user_id))
        else:
            conn.execute('''
                INSERT INTO users (id, username, name, avatar_template, trust_level) VALUES (?, ?, ?, ?, ?)
            ''', (user_id, username, name, avatar_template, trust_level))
        conn.commit()
    except Exception as e:
        print(f"OAuth 用户创建失败: {e}")
        return redirect(f'{APP_BASE_URL}?error=db_error')
    finally:
        conn.close()
    
    # 生成 JWT
    jwt_token = create_jwt_token(user_id, username)
    return redirect(f'{APP_BASE_URL}?token={jwt_token}')

@app.route('/api/user/state')
@jwt_required
def user_state():
    """获取当前用户状态"""
    user_id = request.user['user_id']
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    return jsonify({
        'user': {
            'id': user['id'],
            'username': user['username'],
            'name': user['name'],
            'trustLevel': user['trust_level'],
            'hasUsed': bool(user['has_used'])
        }
    })

@app.route('/api/user/cooldown')
@jwt_required
def user_cooldown():
    """检测当前用户冷却状态"""
    user_id = request.user['user_id']
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        conn.close()
        return jsonify({'inCooldown': False})
    
    # 检查是否已使用过邀请（28天冷却期）
    if user['has_used']:
        from datetime import datetime
        now = datetime.utcnow()
        
        # 查找最后使用邀请码的时间
        last_used = conn.execute('''
            SELECT used_at FROM invite_codes WHERE user_id = ? ORDER BY used_at DESC LIMIT 1
        ''', (user_id,)).fetchone()
        
        cooldown_start = None
        if last_used and last_used['used_at']:
            cooldown_start = parse_datetime(last_used['used_at'])
        elif user['updated_at']:
            cooldown_start = parse_datetime(user['updated_at'])
        
        conn.close()
        
        if cooldown_start:
            cooldown_end = cooldown_start + timedelta(days=28)
            if now < cooldown_end:
                days_left = (cooldown_end - now).days + 1
                cooldown_end_str = cooldown_end.strftime('%Y-%m-%d')
                return jsonify({
                    'inCooldown': True,
                    'daysLeft': days_left,
                    'cooldownEnd': cooldown_end_str
                })
    
    conn.close()
    return jsonify({'inCooldown': False})

@app.route('/api/turnstile/site-key')
def turnstile_site_key():
    """获取 Turnstile site key"""
    return jsonify({'siteKey': CF_TURNSTILE_SITE_KEY})

# ========== 公开 API ==========

@app.route('/api/health')
def health():
    """健康检查端点 - 检查数据库连接状态"""
    health_status = {
        'status': 'ok',
        'time': datetime.now().isoformat(),
        'database': {
            'type': 'PostgreSQL' if USE_POSTGRES else 'SQLite',
            'connected': False
        }
    }
    
    try:
        conn = get_db()
        conn.execute('SELECT 1').fetchone()
        conn.close()
        health_status['database']['connected'] = True
    except Exception as e:
        health_status['status'] = 'degraded'
        health_status['database']['error'] = str(e)
    
    status_code = 200 if health_status['status'] == 'ok' else 503
    return jsonify(health_status), status_code

@app.route('/api/team-accounts/status')
def team_accounts_status():
    """获取所有车位状态（公开）- 使用缓存数据，不实时请求API"""
    conn = get_db()
    accounts = conn.execute('''
        SELECT id, name, max_seats, seats_entitled, seats_in_use, pending_invites, enabled, active_until, last_sync, created_at
        FROM team_accounts WHERE enabled = 1
        ORDER BY id ASC
    ''').fetchall()
    
    result = []
    for acc in accounts:
        result.append({
            'id': acc['id'],
            'name': acc['name'],
            'maxSeats': acc['max_seats'],
            'enabled': bool(acc['enabled']),
            'seatsInUse': acc['seats_in_use'],
            'pendingInvites': acc['pending_invites'] or 0,
            'seatsEntitled': acc['seats_entitled'],
            'activeUntil': acc['active_until'],
            'lastSync': acc['last_sync'],
            'createdAt': acc['created_at']
        })
    
    conn.close()
    return jsonify({'accounts': result})

# ========== 排队通知 API ==========

@app.route('/api/waiting/join', methods=['POST'])
@rate_limit('queue_join')
@jwt_required
def join_waiting_queue():
    """加入排队队列（需要登录）"""
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()
    user_id = request.user['user_id']
    
    # 检查候车室是否开放
    if not WAITING_ROOM_ENABLED:
        return jsonify({'error': '候车室已关闭，暂不接受排队'}), 403
    
    # 邮箱必填验证
    if not email or '@' not in email:
        return jsonify({'error': '请输入有效的邮箱地址'}), 400
    
    conn = get_db()
    
    # 检查用户状态
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': '用户不存在'}), 404
    
    # 检查是否已使用过邀请（28天冷却期）
    if user['has_used']:
        now = datetime.utcnow()
        
        # 查找最后使用邀请码的时间
        last_used = conn.execute('''
            SELECT used_at FROM invite_codes WHERE user_id = ? ORDER BY used_at DESC LIMIT 1
        ''', (user_id,)).fetchone()
        
        cooldown_start = None
        if last_used and last_used['used_at']:
            cooldown_start = parse_datetime(last_used['used_at'])
        elif user['updated_at']:
            # 没有邀请码记录，用用户更新时间作为冷却起点
            cooldown_start = parse_datetime(user['updated_at'])
        
        if cooldown_start:
            cooldown_end = cooldown_start + timedelta(days=28)
            if now < cooldown_end:
                days_left = (cooldown_end - now).days + 1
                cooldown_end_str = cooldown_end.strftime('%Y-%m-%d')
                conn.close()
                return jsonify({
                    'error': f'您已使用过邀请，需等待 {days_left} 天后才能排队',
                    'cooldownEnd': cooldown_end_str,
                    'daysLeft': days_left
                }), 403
    
    # 检查是否已在队列中
    existing = conn.execute('SELECT * FROM waiting_queue WHERE user_id = ?', (user_id,)).fetchone()
    if existing:
        queue_count = conn.execute('SELECT COUNT(*) FROM waiting_queue WHERE notified = 0').fetchone()[0]
        conn.close()
        return jsonify({'message': '您已在排队队列中', 'position': get_queue_position_by_user(user_id), 'email': existing['email'], 'queueCount': queue_count})
    
    # 使用原子操作：检查人数上限 + 插入，防止幻读导致超员
    try:
        if WAITING_ROOM_MAX_QUEUE > 0:
            # 原子操作：只有当队列未满时才插入
            if USE_POSTGRES:
                conn.execute('''
                    INSERT INTO waiting_queue (user_id, email)
                    SELECT %s, %s
                    WHERE (SELECT COUNT(*) FROM waiting_queue) < %s
                ''', (user_id, email if email else None, WAITING_ROOM_MAX_QUEUE))
            else:
                conn.execute('''
                    INSERT INTO waiting_queue (user_id, email)
                    SELECT ?, ?
                    WHERE (SELECT COUNT(*) FROM waiting_queue) < ?
                ''', (user_id, email if email else None, WAITING_ROOM_MAX_QUEUE))
            
            # 检查是否插入成功（rowcount为0表示队列已满）
            if conn.execute('SELECT * FROM waiting_queue WHERE user_id = ?', (user_id,)).fetchone() is None:
                conn.close()
                return jsonify({'error': f'排队人数已达上限（{WAITING_ROOM_MAX_QUEUE}人），请稍后再试'}), 403
        else:
            # 无人数限制，直接插入
            conn.execute('INSERT INTO waiting_queue (user_id, email) VALUES (?, ?)', (user_id, email if email else None))
        
        conn.commit()
    except Exception as e:
        # 并发插入导致唯一约束冲突，说明用户已在队列中
        if 'UNIQUE' in str(e).upper() or 'duplicate' in str(e).lower() or 'IntegrityError' in str(type(e)):
            conn.close()
            return jsonify({'message': '您已在排队队列中', 'position': get_queue_position_by_user(user_id), 'email': email})
        raise e
    
    position = get_queue_position_by_user(user_id)
    queue_count = conn.execute('SELECT COUNT(*) FROM waiting_queue WHERE notified = 0').fetchone()[0]
    conn.close()
    
    return jsonify({'message': '排队成功！有空位时会通知您', 'position': position, 'email': email, 'queueCount': queue_count})

@app.route('/api/waiting/status')
@jwt_required
def waiting_status():
    """获取排队状态（需要登录）"""
    user_id = request.user['user_id']
    
    conn = get_db()
    queue_count = conn.execute('SELECT COUNT(*) FROM waiting_queue WHERE notified = 0').fetchone()[0]
    
    # 检查当前用户是否在队列中
    existing = conn.execute('SELECT * FROM waiting_queue WHERE user_id = ?', (user_id,)).fetchone()
    position = None
    email = None
    if existing:
        position = get_queue_position_by_user(user_id)
        email = existing['email']
    
    conn.close()
    return jsonify({'queueCount': queue_count, 'position': position, 'inQueue': existing is not None, 'email': email})

@app.route('/api/waiting/leave', methods=['POST'])
@jwt_required
def leave_waiting_queue():
    """离开排队队列（需要登录）"""
    user_id = request.user['user_id']
    
    conn = get_db()
    conn.execute('DELETE FROM waiting_queue WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': '已退出排队'})

@app.route('/api/waiting/list')
@jwt_required
def waiting_list():
    """获取排队队列列表（需要登录）"""
    conn = get_db()
    rows = conn.execute('''
        SELECT wq.id, wq.user_id, wq.created_at, wq.notified, wq.notified_at, u.username
        FROM waiting_queue wq
        LEFT JOIN users u ON wq.user_id = u.id
        ORDER BY wq.notified ASC, wq.created_at ASC
    ''').fetchall()
    conn.close()
    
    result = []
    position = 0
    for row in rows:
        # 只有未通知的用户才有排队位置
        if row['notified'] == 0:
            position += 1
            pos = position
        else:
            pos = None  # 已通知的用户不显示位置
        
        result.append({
            'position': pos,
            'username': row['username'] or '未知用户',
            'notified': row['notified'],
            'notifiedAt': row['notified_at']
        })
    
    return jsonify({'queue': result})

def get_queue_position_by_user(user_id: int) -> int:
    """根据用户ID获取排队位置"""
    conn = get_db()
    row = conn.execute('''
        SELECT COUNT(*) + 1 as position FROM waiting_queue 
        WHERE notified = 0 AND created_at < (SELECT created_at FROM waiting_queue WHERE user_id = ?)
    ''', (user_id,)).fetchone()
    conn.close()
    return row['position'] if row else 0

def notify_waiting_users(available_seats: int, force: bool = False):
    """自动给排队用户发送邀请码（按空位数量和车位分配）
    
    Args:
        available_seats: 可用空位数（内部会重新计算）
        force: 是否强制发车（跳过人满发车检查）
    """
    if not MS_TENANT_ID or not MS_CLIENT_ID or not MS_CLIENT_SECRET or not MS_MAIL_FROM:
        print("Microsoft Graph API 邮件未配置，跳过自动发码")
        return 0
    
    conn = get_db()
    
    # 1. 获取各车位的空位数量
    accounts = conn.execute('''
        SELECT id, name, seats_entitled, seats_in_use, pending_invites
        FROM team_accounts WHERE enabled = 1
    ''').fetchall()
    
    # 计算每个车位的可用空位（空位数 = 总席位 - 已用 - 待处理 - 已发出未使用的邀请码）
    available_slots = []
    for acc in accounts:
        # 查询该车位已发出但未使用的邀请码数量（只统计系统自动生成的）
        pending_codes = conn.execute('''
            SELECT COUNT(*) FROM invite_codes 
            WHERE team_account_id = ? AND used = 0 AND auto_generated = 1
        ''', (acc['id'],)).fetchone()[0]
        
        avail = (acc['seats_entitled'] or 0) - (acc['seats_in_use'] or 0) - (acc['pending_invites'] or 0) - pending_codes
        if avail > 0:
            for _ in range(avail):
                available_slots.append({'team_id': acc['id'], 'team_name': acc['name']})
    
    if not available_slots:
        conn.close()
        return 0
    
    # 2. 获取未通知的排队用户数量
    queue_count = conn.execute('''
        SELECT COUNT(*) FROM waiting_queue 
        WHERE notified = 0 AND email IS NOT NULL AND email != ''
    ''').fetchone()[0]
    
    # 人满发车：只有排队人数 >= 空位数才发车（强制发车跳过此检查）
    if not force and queue_count < len(available_slots):
        print(f"[轮询] 排队 {queue_count} 人，空位 {len(available_slots)} 个，等待人满发车...")
        conn.close()
        return 0
    
    # 3. 获取未通知的排队用户（按排队顺序，数量等于空位数）
    users = conn.execute('''
        SELECT wq.*, u.username FROM waiting_queue wq
        LEFT JOIN users u ON wq.user_id = u.id
        WHERE wq.notified = 0 AND wq.email IS NOT NULL AND wq.email != ''
        ORDER BY wq.created_at ASC LIMIT ?
    ''', (len(available_slots),)).fetchall()
    
    if not users:
        conn.close()
        return 0
    
    # 4. 为每个用户生成邀请码并发送
    sent_count = 0
    for i, user in enumerate(users):
        if i >= len(available_slots):
            break
        
        slot = available_slots[i]
        
        # 生成邀请码
        code = generate_code()
        
        # 插入邀请码（绑定车位和用户，标记为系统自动生成）
        conn.execute('''
            INSERT INTO invite_codes (code, team_account_id, user_id, auto_generated) VALUES (?, ?, ?, 1)
        ''', (code, slot['team_id'], user['user_id']))
        
        # 发送邮件（最多重试3次）
        max_retries = 3
        send_success = False
        for retry in range(max_retries):
            if send_invite_code_email(user['email'], code, slot['team_name']):
                send_success = True
                break
            else:
                if retry < max_retries - 1:
                    print(f"发送邮件到 {user['email']} 失败，第 {retry + 1} 次重试...")
                    time.sleep(2)  # 等待2秒后重试
        
        if send_success:
            # 标记已通知
            conn.execute('''
                UPDATE waiting_queue SET notified = 1, notified_at = datetime('now') WHERE id = ?
            ''', (user['id'],))
            conn.commit()
            sent_count += 1
            print(f"已发送邀请码 {code} 到 {user['email']} (车位: {slot['team_name']})")
        else:
            # 发送失败，删除刚生成的邀请码
            conn.execute('DELETE FROM invite_codes WHERE code = ?', (code,))
            conn.commit()
            print(f"发送邀请码到 {user['email']} 失败（已重试 {max_retries} 次）")
    
    conn.close()
    return sent_count

@app.route('/api/invite/check', methods=['POST'])
def check_invite():
    """检查邀请码是否有效"""
    data = request.json or {}
    code = (data.get('code') or '').strip().upper()
    if not code:
        return jsonify({'error': '请输入邀请码'}), 400
    
    conn = get_db()
    row = conn.execute('SELECT * FROM invite_codes WHERE code = ?', (code,)).fetchone()
    conn.close()
    
    if not row:
        return jsonify({'error': '邀请码不存在'}), 404
    if row['used']:
        return jsonify({'error': '邀请码已使用'}), 409
    
    return jsonify({
        'valid': True, 
        'code': code,
        'teamAccountId': row['team_account_id']
    })

@app.route('/api/invite/use', methods=['POST'])
@rate_limit('invite')
@jwt_required
def use_invite():
    """使用邀请码 - 发送真实的 ChatGPT Team 邀请（需要登录）"""
    data = request.json or {}
    code = (data.get('code') or '').strip().upper()
    email = (data.get('email') or '').strip().lower()
    team_account_id = data.get('teamAccountId')
    turnstile_token = (data.get('turnstileToken') or '').strip()
    
    user_id = request.user['user_id']
    
    if not code:
        return jsonify({'error': '请输入邀请码'}), 400
    if not email or '@' not in email:
        return jsonify({'error': '请输入有效邮箱'}), 400
    
    # 验证 Turnstile
    if CF_TURNSTILE_SECRET_KEY:
        if not turnstile_token:
            return jsonify({'error': '请完成人机验证'}), 400
        if not verify_turnstile(turnstile_token, request.remote_addr):
            return jsonify({'error': '人机验证失败'}), 400
    
    conn = get_db()
    row = conn.execute('SELECT * FROM invite_codes WHERE code = ?', (code,)).fetchone()
    
    if not row:
        conn.close()
        return jsonify({'error': '邀请码不存在'}), 404
    if row['used']:
        conn.close()
        return jsonify({'error': '邀请码已使用'}), 409
    
    # 如果邀请码已绑定车位，使用绑定的；否则使用用户选择的
    final_team_id = row['team_account_id'] or team_account_id
    if not final_team_id:
        conn.close()
        return jsonify({'error': '请选择车位'}), 400
    
    # 检查车位是否可用
    account = conn.execute('SELECT * FROM team_accounts WHERE id = ? AND enabled = 1', (final_team_id,)).fetchone()
    if not account:
        conn.close()
        return jsonify({'error': '车位不可用'}), 400
    
    # 检查车位是否配置了凭证（测试模式跳过）
    if not TEST_MODE and (not account['authorization_token'] or not account['account_id']):
        conn.close()
        return jsonify({'error': '车位未配置凭证，无法发送邀请'}), 400
    
    # 测试模式：跳过真实发送，直接成功
    if TEST_MODE:
        print(f"[测试模式] 跳过发送邀请到 {email}，邀请码: {code}")
    else:
        # 调用 ChatGPT Team API 发送邀请
        try:
            result = send_team_invite(account['account_id'], account['authorization_token'], email)
            
            if not result['ok']:
                conn.close()
                return jsonify({'error': f'发送邀请失败: {result["body"]}'}), 400
        except Exception as e:
            conn.close()
            return jsonify({'error': f'发送邀请失败: {str(e)}'}), 500
    
    # 邀请发送成功（或测试模式），标记邀请码已使用
    conn.execute('''
        UPDATE invite_codes 
        SET used = 1, used_email = ?, used_at = datetime('now'), team_account_id = ?, user_id = ?
        WHERE code = ?
    ''', (email, final_team_id, user_id, code))
    # 标记用户已使用邀请
    conn.execute('UPDATE users SET has_used = 1 WHERE id = ?', (user_id,))
    # 从排队队列中移除该用户
    conn.execute('DELETE FROM waiting_queue WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    # 同步车位状态（测试模式跳过）
    if not TEST_MODE:
        try:
            sync_single_account(final_team_id, account['authorization_token'], account['account_id'])
        except:
            pass
    
    return jsonify({'status': 'ok', 'message': '邀请已发送，请查收邮件'})

# ========== TOTP 验证 ==========

def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """验证 TOTP 验证码"""
    if not secret or not code:
        return False
    try:
        # 解码 base32 密钥
        key = base64.b32decode(secret.upper().replace(' ', ''), casefold=True)
        # 当前时间步
        counter = int(time.time()) // 30
        # 检查时间窗口内的验证码
        for i in range(-window, window + 1):
            # 生成 HMAC-SHA1
            msg = struct.pack('>Q', counter + i)
            h = hmac.new(key, msg, hashlib.sha1).digest()
            # 动态截断
            offset = h[-1] & 0x0F
            truncated = struct.unpack('>I', h[offset:offset + 4])[0] & 0x7FFFFFFF
            otp = str(truncated % 1000000).zfill(6)
            if hmac.compare_digest(otp, code):
                return True
        return False
    except Exception:
        return False

# ========== 管理员 API ==========

@app.route('/api/admin/totp-required')
def admin_totp_required():
    """检查是否需要 TOTP"""
    return jsonify({'required': bool(ADMIN_TOTP_SECRET)})

@app.route('/api/admin/login', methods=['POST'])
@rate_limit('admin_login')
def admin_login():
    data = request.json or {}
    password = data.get('password', '')
    totp_code = data.get('totpCode', '')
    
    # 验证密码
    if password != ADMIN_PASSWORD:
        return jsonify({'error': '密码错误'}), 401
    
    # 如果配置了 TOTP，验证验证码
    if ADMIN_TOTP_SECRET:
        if not totp_code:
            return jsonify({'error': '请输入验证码'}), 401
        if not verify_totp(ADMIN_TOTP_SECRET, totp_code):
            return jsonify({'error': '验证码错误'}), 401
    
    session['is_admin'] = True
    return jsonify({'status': 'ok'})

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('is_admin', None)
    return jsonify({'status': 'ok'})

@app.route('/api/admin/stats')
@admin_required
def stats():
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) FROM invite_codes').fetchone()[0]
    used = conn.execute('SELECT COUNT(*) FROM invite_codes WHERE used = 1').fetchone()[0]
    conn.close()
    return jsonify({'total': total, 'used': used, 'available': total - used})

# ========== 车账号管理 ==========

@app.route('/api/admin/team-accounts', methods=['GET'])
@admin_required
def list_team_accounts():
    conn = get_db()
    accounts = conn.execute('''
        SELECT id, name, authorization_token, account_id, max_seats, seats_entitled, seats_in_use, pending_invites, enabled, active_until, last_sync, created_at
        FROM team_accounts ORDER BY id ASC
    ''').fetchall()
    
    result = []
    for acc in accounts:
        result.append({
            'id': acc['id'],
            'name': acc['name'],
            'authorizationToken': acc['authorization_token'] or '',
            'accountId': acc['account_id'] or '',
            'maxSeats': acc['max_seats'],
            'enabled': bool(acc['enabled']),
            'seatsInUse': acc['seats_in_use'],
            'pendingInvites': acc['pending_invites'] or 0,
            'seatsEntitled': acc['seats_entitled'],
            'activeUntil': acc['active_until'],
            'lastSync': acc['last_sync'],
            'createdAt': acc['created_at']
        })
    
    conn.close()
    return jsonify({'accounts': result})

@app.route('/api/admin/team-accounts', methods=['POST'])
@admin_required
def create_team_account():
    data = request.json or {}
    name = (data.get('name') or '').strip()
    authorization_token = (data.get('authorizationToken') or '').strip()
    account_id = (data.get('accountId') or '').strip()
    max_seats = int(data.get('maxSeats', 5))
    active_until = (data.get('activeUntil') or '').strip() or None
    
    if not name:
        return jsonify({'error': '请输入车位名称'}), 400
    
    conn = get_db()
    cursor = conn.execute(
        'INSERT INTO team_accounts (name, authorization_token, account_id, max_seats, seats_entitled, active_until) VALUES (?, ?, ?, ?, ?, ?)',
        (name, authorization_token, account_id, max_seats, max_seats, active_until)
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # 如果有 token 和 account_id，异步同步一次状态
    if authorization_token and account_id:
        def safe_sync():
            try:
                sync_single_account(new_id, authorization_token, account_id)
            except Exception as e:
                print(f"[同步失败] 车位 {name}: {e}")
        threading.Thread(target=safe_sync, daemon=True).start()
    
    log_admin_action('创建车位', f'名称: {name}, ID: {new_id}')
    return jsonify({'id': new_id, 'name': name, 'maxSeats': max_seats})

@app.route('/api/admin/team-accounts/<int:account_id>', methods=['PUT'])
@admin_required
def update_team_account(account_id):
    data = request.json or {}
    name = (data.get('name') or '').strip()
    authorization_token = (data.get('authorizationToken') or '').strip()
    acc_id = (data.get('accountId') or '').strip()
    max_seats = int(data.get('maxSeats', 5))
    enabled = 1 if data.get('enabled', True) else 0
    active_until = (data.get('activeUntil') or '').strip() or None
    
    conn = get_db()
    conn.execute('''
        UPDATE team_accounts SET name = ?, authorization_token = ?, account_id = ?, max_seats = ?, enabled = ?, active_until = ?
        WHERE id = ?
    ''', (name, authorization_token, acc_id, max_seats, enabled, active_until, account_id))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'ok'})

@app.route('/api/admin/team-accounts/<int:account_id>/sync', methods=['POST'])
@admin_required
def sync_team_account(account_id):
    """同步单个车账号的状态"""
    conn = get_db()
    acc = conn.execute('SELECT * FROM team_accounts WHERE id = ?', (account_id,)).fetchone()
    if not acc:
        conn.close()
        return jsonify({'error': '车账号不存在'}), 404
    
    if not acc['authorization_token'] or not acc['account_id']:
        conn.close()
        return jsonify({'error': '请先配置 Authorization Token 和 Account ID'}), 400
    
    try:
        data = fetch_team_status(acc['account_id'], acc['authorization_token'])
        
        conn.execute('''
            UPDATE team_accounts SET seats_in_use = ?, seats_entitled = ?, pending_invites = ?, active_until = ?, last_sync = datetime('now')
            WHERE id = ?
        ''', (data['seats_in_use'], data['seats_entitled'], data.get('pending_invites', 0), data.get('active_until'), account_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'ok',
            'seatsInUse': data['seats_in_use'],
            'seatsEntitled': data['seats_entitled'],
            'pendingInvites': data.get('pending_invites', 0),
            'activeUntil': data.get('active_until')
        })
    except requests.HTTPError as e:
        conn.close()
        return jsonify({'error': f'API 请求失败: {e.response.status_code if e.response else str(e)}'}), 400
    except Exception as e:
        conn.close()
        return jsonify({'error': f'同步失败: {str(e)}'}), 500

@app.route('/api/admin/team-accounts/sync-all', methods=['POST'])
@admin_required
def sync_all_team_accounts():
    """同步所有车账号状态"""
    conn = get_db()
    accounts = conn.execute('SELECT * FROM team_accounts WHERE enabled = 1').fetchall()
    
    results = []
    total_available = 0
    for acc in accounts:
        if not acc['authorization_token'] or not acc['account_id']:
            results.append({'id': acc['id'], 'name': acc['name'], 'error': '未配置凭证'})
            continue
        
        try:
            data = fetch_team_status(acc['account_id'], acc['authorization_token'])
            
            conn.execute('''
                UPDATE team_accounts SET seats_in_use = ?, seats_entitled = ?, pending_invites = ?, active_until = ?, last_sync = datetime('now')
                WHERE id = ?
            ''', (data['seats_in_use'], data['seats_entitled'], data.get('pending_invites', 0), data.get('active_until'), acc['id']))
            
            avail = data['seats_entitled'] - data['seats_in_use'] - data.get('pending_invites', 0)
            if avail > 0:
                total_available += avail
            
            results.append({
                'id': acc['id'], 
                'name': acc['name'], 
                'seatsInUse': data['seats_in_use'],
                'seatsEntitled': data['seats_entitled'],
                'activeUntil': data.get('active_until')
            })
        except Exception as e:
            results.append({'id': acc['id'], 'name': acc['name'], 'error': str(e)})
    
    conn.commit()
    conn.close()
    
    # 同步后自动触发发码（如果有空位）
    if total_available > 0:
        try:
            notify_waiting_users(total_available)
        except Exception as e:
            print(f"自动发码失败: {e}")
    
    return jsonify({'results': results})

@app.route('/api/admin/send-invite-codes', methods=['POST'])
@admin_required
def admin_send_invite_codes():
    """手动触发给排队用户发送邀请码（强制发车，跳过人满检查）"""
    try:
        sent = notify_waiting_users(999, force=True)  # 强制发车
        return jsonify({'status': 'ok', 'message': f'已强制发车，发送 {sent or 0} 个邀请码'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/team-accounts/<int:account_id>', methods=['DELETE'])
@admin_required
def delete_team_account(account_id):
    conn = get_db()
    # 检查是否有关联的邀请码
    count = conn.execute(
        'SELECT COUNT(*) FROM invite_codes WHERE team_account_id = ?', 
        (account_id,)
    ).fetchone()[0]
    
    if count > 0:
        conn.close()
        return jsonify({'error': '该车位下有邀请码，无法删除'}), 400
    
    conn.execute('DELETE FROM team_accounts WHERE id = ?', (account_id,))
    conn.commit()
    conn.close()
    
    log_admin_action('删除车位', f'ID: {account_id}')
    return jsonify({'status': 'deleted'})

# ========== 邀请码管理 ==========

@app.route('/api/admin/codes', methods=['GET'])
@admin_required
def list_codes():
    conn = get_db()
    rows = conn.execute('''
        SELECT c.*, t.name as team_name, u.username as used_username
        FROM invite_codes c
        LEFT JOIN team_accounts t ON c.team_account_id = t.id
        LEFT JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
    ''').fetchall()
    conn.close()
    return jsonify({'codes': [dict(r.items()) for r in rows]})

@app.route('/api/admin/codes', methods=['POST'])
@admin_required
def create_codes():
    data = request.json or {}
    count = min(max(int(data.get('count', 1)), 1), 50)
    team_account_id = data.get('teamAccountId')
    
    conn = get_db()
    
    # 验证车账号
    if team_account_id:
        acc = conn.execute('SELECT * FROM team_accounts WHERE id = ?', (team_account_id,)).fetchone()
        if not acc:
            conn.close()
            return jsonify({'error': '车位不存在'}), 400
    
    codes = []
    for _ in range(count):
        code = generate_code()
        try:
            conn.execute(
                'INSERT INTO invite_codes (code, team_account_id) VALUES (?, ?)', 
                (code, team_account_id)
            )
            codes.append(code)
        except Exception as e:
            # 唯一约束冲突，跳过
            if 'UNIQUE' in str(e).upper() or 'duplicate' in str(e).lower():
                continue
            raise e
    conn.commit()
    conn.close()
    
    return jsonify({'codes': codes, 'created': len(codes)})

@app.route('/api/admin/codes/<int:code_id>', methods=['DELETE'])
@admin_required
def delete_code(code_id):
    conn = get_db()
    conn.execute('DELETE FROM invite_codes WHERE id = ?', (code_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'deleted'})

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def list_users():
    conn = get_db()
    rows = conn.execute('''
        SELECT * FROM users ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    return jsonify({'users': [dict(r.items()) for r in rows]})

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    data = request.json or {}
    has_used = 1 if data.get('hasUsed') else 0
    
    conn = get_db()
    conn.execute('''
        UPDATE users SET has_used = ?, updated_at = datetime('now')
        WHERE id = ?
    ''', (has_used, user_id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'deleted'})

# ========== 排队队列管理 ==========

@app.route('/api/admin/queue', methods=['GET'])
@admin_required
def list_queue():
    conn = get_db()
    rows = conn.execute('''
        SELECT q.*, u.username, u.name as user_name
        FROM waiting_queue q
        LEFT JOIN users u ON q.user_id = u.id
        ORDER BY q.created_at ASC
    ''').fetchall()
    waiting = conn.execute('SELECT COUNT(*) FROM waiting_queue WHERE notified = 0').fetchone()[0]
    notified = conn.execute('SELECT COUNT(*) FROM waiting_queue WHERE notified = 1').fetchone()[0]
    conn.close()
    return jsonify({
        'queue': [dict(r.items()) for r in rows],
        'waiting': waiting,
        'notified': notified,
        'total': waiting + notified
    })

@app.route('/api/admin/queue/<int:queue_id>', methods=['DELETE'])
@admin_required
def delete_queue_item(queue_id):
    conn = get_db()
    conn.execute('DELETE FROM waiting_queue WHERE id = ?', (queue_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'deleted'})

@app.route('/api/admin/queue/clear-notified', methods=['POST'])
@admin_required
def clear_notified_queue():
    conn = get_db()
    cursor = conn.execute('DELETE FROM waiting_queue WHERE notified = 1')
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok', 'deleted': deleted})

@app.route('/api/admin/queue/clear-all', methods=['POST'])
@admin_required
def clear_all_queue():
    """删除所有排队记录"""
    conn = get_db()
    cursor = conn.execute('DELETE FROM waiting_queue')
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    log_admin_action('清空排队队列', f'删除 {deleted} 条记录')
    return jsonify({'status': 'ok', 'deleted': deleted})

@app.route('/api/admin/users/clear-all', methods=['POST'])
@admin_required
def clear_all_users():
    """删除所有用户"""
    conn = get_db()
    cursor = conn.execute('DELETE FROM users')
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    log_admin_action('清空所有用户', f'删除 {deleted} 条记录')
    return jsonify({'status': 'ok', 'deleted': deleted})

@app.route('/api/admin/codes/clear-all', methods=['POST'])
@admin_required
def clear_all_codes():
    """删除所有邀请码"""
    conn = get_db()
    cursor = conn.execute('DELETE FROM invite_codes')
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    log_admin_action('清空所有邀请码', f'删除 {deleted} 条记录')
    return jsonify({'status': 'ok', 'deleted': deleted})

# ========== 冷却用户管理 ==========

@app.route('/api/admin/cooldown-users', methods=['GET'])
@admin_required
def list_cooldown_users():
    """获取冷却中的用户列表（has_used=1的用户）"""
    conn = get_db()
    
    if USE_POSTGRES:
        rows = conn.execute('''
            SELECT u.id, u.username, u.name, c.used_email, 
                   COALESCE(c.used_at, u.updated_at) as used_at, 
                   t.name as team_name
            FROM users u
            LEFT JOIN invite_codes c ON u.id = c.user_id AND c.used = 1
            LEFT JOIN team_accounts t ON c.team_account_id = t.id
            WHERE u.has_used = 1
            GROUP BY u.id, u.username, u.name, c.used_email, c.used_at, u.updated_at, t.name
            ORDER BY COALESCE(c.used_at, u.updated_at) DESC
        ''').fetchall()
    else:
        rows = conn.execute('''
            SELECT u.id, u.username, u.name, c.used_email, 
                   COALESCE(c.used_at, u.updated_at) as used_at, 
                   t.name as team_name,
                   datetime(COALESCE(c.used_at, u.updated_at), '+28 days') as cooldown_end,
                   MAX(0, CAST(julianday(datetime(COALESCE(c.used_at, u.updated_at), '+28 days')) - julianday('now') AS INTEGER)) as days_left
            FROM users u
            LEFT JOIN invite_codes c ON u.id = c.user_id AND c.used = 1
            LEFT JOIN team_accounts t ON c.team_account_id = t.id
            WHERE u.has_used = 1
            GROUP BY u.id
            ORDER BY used_at DESC
        ''').fetchall()
    conn.close()
    
    # 计算冷却结束时间和剩余天数
    result = []
    now = datetime.utcnow()
    for row in rows:
        used_at = parse_datetime(row['used_at'])
        if used_at:
            cooldown_end = used_at + timedelta(days=28)
            days_left = max(0, (cooldown_end - now).days)
        else:
            cooldown_end = None
            days_left = 0
        
        result.append({
            'id': row['id'],
            'username': row['username'],
            'name': row['name'],
            'used_email': row['used_email'],
            'used_at': str(row['used_at']) if row['used_at'] else None,
            'team_name': row['team_name'],
            'cooldown_end': cooldown_end.strftime('%Y-%m-%d %H:%M') if cooldown_end else None,
            'days_left': days_left
        })
    
    return jsonify({
        'users': result,
        'count': len(result)
    })

@app.route('/api/admin/cooldown-users/clear-all', methods=['POST'])
@admin_required
def clear_all_cooldown():
    """清除所有用户的冷却状态（重置 has_used 为 0）"""
    conn = get_db()
    cursor = conn.execute('UPDATE users SET has_used = 0')
    updated = cursor.rowcount
    conn.commit()
    conn.close()
    log_admin_action('清除所有冷却', f'更新 {updated} 条记录')
    return jsonify({'status': 'ok', 'updated': updated})

# ========== 管理员日志 API ==========

@app.route('/api/admin/logs', methods=['GET'])
@admin_required
def get_admin_logs():
    """获取管理员操作日志"""
    limit = min(int(request.args.get('limit', 50)), 200)
    conn = get_db()
    rows = conn.execute('''
        SELECT id, action, details, ip_address, created_at 
        FROM admin_logs ORDER BY created_at DESC LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return jsonify({'logs': [dict(r.items()) for r in rows]})

# ========== 发车监控 API ==========

@app.route('/api/admin/monitor')
@admin_required
def get_monitor_status():
    """获取发车监控状态"""
    conn = get_db()
    
    # 获取排队人数（未通知的）
    queue_count = conn.execute('SELECT COUNT(*) FROM waiting_queue WHERE notified = 0').fetchone()[0]
    
    # 获取已通知但未使用的人数
    notified_count = conn.execute('SELECT COUNT(*) FROM waiting_queue WHERE notified = 1').fetchone()[0]
    
    # 获取待使用邀请码数（只统计系统自动生成的）
    pending_codes = conn.execute('SELECT COUNT(*) FROM invite_codes WHERE used = 0 AND auto_generated = 1').fetchone()[0]
    
    # 获取各车位空位
    accounts = conn.execute('''
        SELECT id, name, seats_entitled, seats_in_use, pending_invites, last_sync
        FROM team_accounts WHERE enabled = 1
    ''').fetchall()
    
    available_slots = 0
    team_status = []
    for acc in accounts:
        # 查询该车位已发出但未使用的邀请码数量（只统计系统自动生成的）
        acc_pending_codes = conn.execute('''
            SELECT COUNT(*) FROM invite_codes 
            WHERE team_account_id = ? AND used = 0 AND auto_generated = 1
        ''', (acc['id'],)).fetchone()[0]
        
        avail = max(0, (acc['seats_entitled'] or 0) - (acc['seats_in_use'] or 0) - (acc['pending_invites'] or 0) - acc_pending_codes)
        available_slots += avail
        team_status.append({
            'id': acc['id'],
            'name': acc['name'],
            'available': avail,
            'total': acc['seats_entitled'] or 0,
            'inUse': acc['seats_in_use'] or 0,
            'pendingInvites': acc['pending_invites'] or 0,
            'pendingCodes': acc_pending_codes,
            'lastSync': acc['last_sync']
        })
    
    # 获取最早的未使用邀请码创建时间（只统计系统自动生成的，用于计算过期倒计时）
    oldest_code = conn.execute('''
        SELECT created_at FROM invite_codes WHERE used = 0 AND auto_generated = 1 ORDER BY created_at ASC LIMIT 1
    ''').fetchone()
    
    conn.close()
    
    # 计算状态
    status = 'idle'
    status_text = '空闲'
    expire_countdown = None
    
    if pending_codes > 0:
        status = 'waiting'
        status_text = f'等待 {pending_codes} 个邀请码被使用'
        if oldest_code:
            created = parse_datetime(oldest_code['created_at'])
            if created:
                expire_time = created + timedelta(seconds=INVITE_CODE_EXPIRE)
                remaining = (expire_time - datetime.utcnow()).total_seconds()
                expire_countdown = max(0, int(remaining))
    elif queue_count > 0 and available_slots > 0:
        if queue_count >= available_slots:
            status = 'ready'
            status_text = f'人满发车就绪 ({queue_count}人/{available_slots}位)'
        else:
            status = 'waiting_queue'
            status_text = f'等待人满 ({queue_count}人/{available_slots}位)'
    elif queue_count > 0:
        status = 'no_slots'
        status_text = f'无空位 ({queue_count}人排队)'
    elif available_slots > 0:
        status = 'no_queue'
        status_text = f'无排队 ({available_slots}空位)'
    
    return jsonify({
        'queueCount': queue_count,
        'notifiedCount': notified_count,
        'pendingCodes': pending_codes,
        'availableSlots': available_slots,
        'status': status,
        'statusText': status_text,
        'expireCountdown': expire_countdown,
        'inviteCodeExpire': INVITE_CODE_EXPIRE,
        'pollWaitTime': POLL_WAIT_TIME,
        'syncInterval': SYNC_INTERVAL,
        'testMode': TEST_MODE,
        'dispatchMode': DISPATCH_MODE,
        'databaseType': 'PostgreSQL' if USE_POSTGRES else 'SQLite',
        'teams': team_status,
        'lastSyncTime': monitor_state.get('last_sync_time'),
        'lastBatchTime': monitor_state.get('last_batch_time')
    })

@app.route('/api/admin/dispatch-mode', methods=['POST'])
@admin_required
def set_dispatch_mode():
    """设置发车模式"""
    global DISPATCH_MODE
    data = request.json or {}
    mode = data.get('mode', 'auto')
    if mode not in ('auto', 'manual'):
        return jsonify({'error': '无效的模式'}), 400
    DISPATCH_MODE = mode
    save_setting('dispatch_mode', mode)
    return jsonify({'status': 'ok', 'mode': DISPATCH_MODE})

# ========== 候车室设置 API ==========

@app.route('/api/admin/waiting-room-settings', methods=['GET'])
@admin_required
def get_waiting_room_settings():
    """获取候车室设置"""
    conn = get_db()
    queue_count = conn.execute('SELECT COUNT(*) FROM waiting_queue').fetchone()[0]
    conn.close()
    return jsonify({
        'enabled': WAITING_ROOM_ENABLED,
        'maxQueue': WAITING_ROOM_MAX_QUEUE,
        'currentQueue': queue_count
    })

@app.route('/api/admin/waiting-room-settings', methods=['POST'])
@admin_required
def set_waiting_room_settings():
    """设置候车室"""
    global WAITING_ROOM_ENABLED, WAITING_ROOM_MAX_QUEUE
    data = request.json or {}
    
    if 'enabled' in data:
        WAITING_ROOM_ENABLED = bool(data['enabled'])
        save_setting('waiting_room_enabled', 'true' if WAITING_ROOM_ENABLED else 'false')
    if 'maxQueue' in data:
        WAITING_ROOM_MAX_QUEUE = max(0, int(data['maxQueue']))
        save_setting('waiting_room_max_queue', str(WAITING_ROOM_MAX_QUEUE))
    
    return jsonify({
        'status': 'ok',
        'enabled': WAITING_ROOM_ENABLED,
        'maxQueue': WAITING_ROOM_MAX_QUEUE
    })

# ========== 同步间隔设置 API ==========

@app.route('/api/admin/sync-interval', methods=['GET'])
@admin_required
def get_sync_interval():
    """获取同步间隔设置"""
    return jsonify({
        'syncInterval': SYNC_INTERVAL
    })

@app.route('/api/admin/sync-interval', methods=['POST'])
@admin_required
def set_sync_interval():
    """设置同步间隔"""
    global SYNC_INTERVAL
    data = request.json or {}
    
    if 'syncInterval' in data:
        interval = int(data['syncInterval'])
        # 验证有效值: 300(5min), 900(15min), 1800(30min), 3600(1h), 7200(2h)
        valid_intervals = [300, 900, 1800, 3600, 7200]
        if interval not in valid_intervals:
            return jsonify({'error': '无效的同步间隔'}), 400
        SYNC_INTERVAL = interval
        save_setting('sync_interval', str(SYNC_INTERVAL))
    
    return jsonify({
        'status': 'ok',
        'syncInterval': SYNC_INTERVAL
    })

# ========== 后台自动同步 ==========

# 邀请码有效期（秒）
INVITE_CODE_EXPIRE = int(os.environ.get('INVITE_CODE_EXPIRE', 1800))  # 默认30分钟
# 轮询等待时间（秒）
POLL_WAIT_TIME = int(os.environ.get('POLL_WAIT_TIME', 60))  # 默认1分钟

# 发车监控状态（全局变量）
monitor_state = {
    'last_sync_time': None,       # 最后同步时间
    'last_batch_time': None,      # 最后发车时间
    'pending_codes': 0,           # 待使用邀请码数
    'queue_count': 0,             # 排队人数
    'available_slots': 0,         # 可用空位
    'status': 'idle',             # 状态: idle/waiting/sending/cooldown
    'status_text': '空闲',        # 状态文字
    'next_action_time': None,     # 下次操作时间
}

# 已满车位的同步间隔（秒）- 30分钟
FULL_CAR_SYNC_INTERVAL = int(os.environ.get('FULL_CAR_SYNC_INTERVAL', 1800))

def sync_team_accounts():
    """同步所有车账号状态，返回总空位数
    
    优化策略：已满的车位每30分钟同步一次，有空位的车位每次都同步
    """
    conn = get_db()
    accounts = conn.execute(
        'SELECT * FROM team_accounts WHERE enabled = 1 AND authorization_token IS NOT NULL AND account_id IS NOT NULL'
    ).fetchall()
    
    total_available = 0
    now = datetime.utcnow()
    
    for acc in accounts:
        # 计算当前已知的空位数
        current_available = (acc['seats_entitled'] or 0) - (acc['seats_in_use'] or 0) - (acc['pending_invites'] or 0)
        
        # 检查是否需要同步
        need_sync = True
        if current_available <= 0 and acc['last_sync']:
            # 已满的车位，检查上次同步时间
            try:
                last_sync_str = str(acc['last_sync']).replace(' ', 'T')
                if '+' not in last_sync_str and 'Z' not in last_sync_str:
                    last_sync = datetime.fromisoformat(last_sync_str)
                else:
                    last_sync = datetime.fromisoformat(last_sync_str.replace('Z', '+00:00'))
                time_since_sync = (now - last_sync.replace(tzinfo=None)).total_seconds()
                if time_since_sync < FULL_CAR_SYNC_INTERVAL:
                    # 30分钟内已同步过，跳过
                    need_sync = False
                    print(f"[跳过同步] {acc['name']} 已满，{int(FULL_CAR_SYNC_INTERVAL - time_since_sync)}秒后再同步")
            except:
                pass
        
        if not need_sync:
            continue
        
        try:
            data = fetch_team_status(acc['account_id'], acc['authorization_token'])
            conn.execute('''
                UPDATE team_accounts SET seats_in_use = ?, seats_entitled = ?, pending_invites = ?, active_until = ?, last_sync = datetime('now')
                WHERE id = ?
            ''', (data['seats_in_use'], data['seats_entitled'], data.get('pending_invites', 0), data.get('active_until'), acc['id']))
            available = data['seats_entitled'] - data['seats_in_use'] - data.get('pending_invites', 0)
            if available > 0:
                total_available += available
        except Exception as e:
            print(f"[同步失败] {acc['name']}: {e}")
    
    conn.commit()
    conn.close()
    return total_available

def get_pending_invite_codes_count():
    """获取已发出但未使用的邀请码数量（只统计系统自动生成的）"""
    conn = get_db()
    count = conn.execute('SELECT COUNT(*) FROM invite_codes WHERE used = 0 AND auto_generated = 1').fetchone()[0]
    conn.close()
    return count

def cleanup_expired_invite_codes():
    """清理过期的邀请码（超过有效期未使用的系统自动生成邀请码）- 同时移除用户出队列"""
    conn = get_db()
    
    # 查找过期的邀请码（只清理系统自动生成的，创建时间超过有效期且未使用）
    if USE_POSTGRES:
        expired = conn.execute(f'''
            SELECT ic.*, wq.id as queue_id FROM invite_codes ic
            LEFT JOIN waiting_queue wq ON ic.user_id = wq.user_id
            WHERE ic.used = 0 AND ic.auto_generated = 1 AND ic.created_at + INTERVAL '{INVITE_CODE_EXPIRE} seconds' < NOW()
        ''').fetchall()
    else:
        expired = conn.execute(f'''
            SELECT ic.*, wq.id as queue_id FROM invite_codes ic
            LEFT JOIN waiting_queue wq ON ic.user_id = wq.user_id
            WHERE ic.used = 0 AND ic.auto_generated = 1 AND datetime(ic.created_at, '+{INVITE_CODE_EXPIRE} seconds') < datetime('now')
        ''').fetchall()
    
    if expired:
        print(f"[清理] 发现 {len(expired)} 个过期邀请码")
        for code in expired:
            # 删除邀请码
            conn.execute('DELETE FROM invite_codes WHERE id = ?', (code['id'],))
            # 从队列中移除用户（邀请码过期视为放弃排队）
            if code['user_id']:
                conn.execute('DELETE FROM waiting_queue WHERE user_id = ?', (code['user_id'],))
                print(f"[清理] 已删除过期邀请码 {code['code']}，用户已移出队列")
            else:
                print(f"[清理] 已删除过期邀请码 {code['code']}")
        conn.commit()
    
    conn.close()
    return len(expired) if expired else 0

def background_sync():
    """后台线程：智能轮询发码"""
    global monitor_state
    last_batch_time = None  # 上一批邀请码发送时间
    
    while True:
        try:
            # 1. 同步车位状态
            total_available = sync_team_accounts()
            monitor_state['last_sync_time'] = datetime.utcnow().isoformat() + 'Z'
            monitor_state['available_slots'] = total_available
            
            # 2. 检查是否有未使用的邀请码
            pending_codes = get_pending_invite_codes_count()
            monitor_state['pending_codes'] = pending_codes
            
            if pending_codes > 0:
                monitor_state['status'] = 'waiting'
                monitor_state['status_text'] = f'等待 {pending_codes} 个邀请码被使用'
                
                # 有未使用的邀请码，检查是否过期
                expired_count = cleanup_expired_invite_codes()
                
                if expired_count == 0:
                    # 没有过期的，继续等待
                    print(f"[轮询] 等待 {pending_codes} 个邀请码被使用...")
                    time.sleep(SYNC_INTERVAL)
                    continue
                else:
                    # 有过期的被清理了，等待1分钟后继续
                    monitor_state['status'] = 'cooldown'
                    monitor_state['status_text'] = f'已清理 {expired_count} 个过期码，冷却中'
                    monitor_state['next_action_time'] = (datetime.utcnow() + timedelta(seconds=POLL_WAIT_TIME)).isoformat() + 'Z'
                    print(f"[轮询] 已清理 {expired_count} 个过期邀请码，等待 {POLL_WAIT_TIME} 秒后继续")
                    time.sleep(POLL_WAIT_TIME)
                    continue
            
            # 3. 没有未使用的邀请码，检查是否需要发新的
            if total_available > 0:
                # 手动模式：不自动发车，等待管理员手动触发
                if DISPATCH_MODE == 'manual':
                    monitor_state['status'] = 'manual_wait'
                    monitor_state['status_text'] = '手动模式 - 等待管理员发车'
                    time.sleep(SYNC_INTERVAL)
                    continue
                
                # 如果刚发完一批，等待1分钟
                if last_batch_time and (time.time() - last_batch_time) < POLL_WAIT_TIME:
                    wait_time = POLL_WAIT_TIME - (time.time() - last_batch_time)
                    monitor_state['status'] = 'cooldown'
                    monitor_state['status_text'] = f'批次冷却中，{int(wait_time)}秒后继续'
                    monitor_state['next_action_time'] = (datetime.utcnow() + timedelta(seconds=wait_time)).isoformat() + 'Z'
                    print(f"[轮询] 上批邀请码已用完，等待 {int(wait_time)} 秒后发送下一批")
                    time.sleep(wait_time)
                    continue
                
                # 发送新一批邀请码
                monitor_state['status'] = 'sending'
                monitor_state['status_text'] = '正在发送邀请码...'
                notify_waiting_users(total_available)
                last_batch_time = time.time()
                monitor_state['last_batch_time'] = datetime.utcnow().isoformat() + 'Z'
            else:
                monitor_state['status'] = 'idle'
                monitor_state['status_text'] = '无空位'
            
            time.sleep(SYNC_INTERVAL)
            
        except Exception as e:
            monitor_state['status'] = 'error'
            monitor_state['status_text'] = f'错误: {str(e)}'
            print(f"[后台同步错误] {e}")
            time.sleep(SYNC_INTERVAL)

if __name__ == '__main__':
    init_db()
    
    # 启动后台同步线程
    sync_thread = threading.Thread(target=background_sync, daemon=True)
    sync_thread.start()
    print(f"✅ 后台同步已启动，每 {SYNC_INTERVAL} 秒更新一次")
    
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    print(f"启动服务: http://localhost:{port}")
    print(f"管理后台: http://localhost:{port}/admin")
    if ADMIN_PASSWORD == 'admin123':
        print(f"⚠️  使用默认管理密码，请在 .env 中设置 ADMIN_PASSWORD")
    app.run(host='0.0.0.0', port=port, debug=debug, use_reloader=False)
