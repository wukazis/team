#!/usr/bin/env python3

import os
import sqlite3
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

load_dotenv()

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

# SendGrid 邮件配置
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY', '')
SENDGRID_FROM_EMAIL = os.environ.get('SENDGRID_FROM_EMAIL', '')

# JWT 配置
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_EXPIRY_HOURS = 24

# OAuth state 存储
oauth_states = {}

# 获取当前脚本所在目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path='')

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

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
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
    # 添加 active_until 列（如果不存在）
    try:
        conn.execute('ALTER TABLE team_accounts ADD COLUMN active_until TEXT')
    except sqlite3.OperationalError:
        pass  # 列已存在
    # 添加 has_used 列（如果不存在）
    try:
        conn.execute('ALTER TABLE users ADD COLUMN has_used INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # 列已存在
    # 添加 pending_invites 列（如果不存在）
    try:
        conn.execute('ALTER TABLE team_accounts ADD COLUMN pending_invites INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # 列已存在
    
    # 创建排队表
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
    # 添加 user_id 列（如果不存在）
    try:
        conn.execute('ALTER TABLE waiting_queue ADD COLUMN user_id INTEGER REFERENCES users(id)')
    except sqlite3.OperationalError:
        pass  # 列已存在
    # 修改 email 为可空
    # SQLite 不支持直接修改列，但新记录可以为空
    conn.commit()
    conn.close()

def generate_code():
    return secrets.token_urlsafe(8).upper()[:12]

# ========== SendGrid 邮件 ==========

def send_notification_email(to_email: str, available_seats: int) -> bool:
    """发送空位通知邮件"""
    if not SENDGRID_API_KEY or not SENDGRID_FROM_EMAIL:
        print("SendGrid 未配置")
        return False
    
    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail
        
        message = Mail(
            from_email=SENDGRID_FROM_EMAIL,
            to_emails=to_email,
            subject='🎉 候车室有空位啦！',
            html_content=f'''
            <div style="font-family: system-ui, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2563eb;">候车室通知</h2>
                <p>您好！</p>
                <p>您排队等待的车位现在有 <strong style="color: #16a34a;">{available_seats}</strong> 个空位可用。</p>
                <p>请尽快前往候车室使用邀请码领取席位：</p>
                <p><a href="{APP_BASE_URL}" style="display: inline-block; background: #2563eb; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none;">前往领取</a></p>
                <p style="color: #64748b; font-size: 14px; margin-top: 20px;">如果您已经领取或不再需要，请忽略此邮件。</p>
            </div>
            '''
        )
        
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        return response.status_code in [200, 201, 202]
    except Exception as e:
        print(f"发送邮件失败: {e}")
        return False

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

@app.route('/api/turnstile/site-key')
def turnstile_site_key():
    """获取 Turnstile site key"""
    return jsonify({'siteKey': CF_TURNSTILE_SITE_KEY})

# ========== 公开 API ==========

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'time': datetime.now().isoformat()})

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
@jwt_required
def join_waiting_queue():
    """加入排队队列（需要登录）"""
    data = request.json or {}
    email = (data.get('email') or '').strip().lower()
    user_id = request.user['user_id']
    
    conn = get_db()
    
    # 检查用户状态
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': '用户不存在'}), 404
    
    # 检查是否已使用过邀请（30天冷却期）
    if user['has_used']:
        # 查找最后使用邀请码的时间
        last_used = conn.execute('''
            SELECT used_at FROM invite_codes WHERE user_id = ? ORDER BY used_at DESC LIMIT 1
        ''', (user_id,)).fetchone()
        
        if last_used and last_used['used_at']:
            from datetime import datetime
            used_time = datetime.fromisoformat(last_used['used_at'].replace('Z', '+00:00').replace(' ', 'T'))
            cooldown_end = used_time + timedelta(days=30)
            now = datetime.utcnow()
            
            if now < cooldown_end:
                days_left = (cooldown_end - now).days + 1
                conn.close()
                return jsonify({'error': f'您已使用过邀请，需等待 {days_left} 天后才能排队'}), 403
    
    # 检查是否已在队列中
    existing = conn.execute('SELECT * FROM waiting_queue WHERE user_id = ?', (user_id,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'message': '您已在排队队列中', 'position': get_queue_position_by_user(user_id)})
    
    conn.execute('INSERT INTO waiting_queue (user_id, email) VALUES (?, ?)', (user_id, email if email else None))
    conn.commit()
    position = get_queue_position_by_user(user_id)
    conn.close()
    
    return jsonify({'message': '排队成功！有空位时会通知您', 'position': position})

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
    if existing:
        position = get_queue_position_by_user(user_id)
    
    conn.close()
    return jsonify({'queueCount': queue_count, 'position': position, 'inQueue': existing is not None})

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

def get_queue_position_by_user(user_id: int) -> int:
    """根据用户ID获取排队位置"""
    conn = get_db()
    row = conn.execute('''
        SELECT COUNT(*) + 1 as position FROM waiting_queue 
        WHERE notified = 0 AND created_at < (SELECT created_at FROM waiting_queue WHERE user_id = ?)
    ''', (user_id,)).fetchone()
    conn.close()
    return row['position'] if row else 0

def notify_waiting_users(available_seats: int):
    """通知排队用户有空位"""
    if available_seats <= 0 or not SENDGRID_API_KEY:
        return
    
    conn = get_db()
    # 获取未通知的排队用户（按排队顺序，最多通知空位数的2倍）
    users = conn.execute('''
        SELECT * FROM waiting_queue WHERE notified = 0 
        ORDER BY created_at ASC LIMIT ?
    ''', (available_seats * 2,)).fetchall()
    
    for user in users:
        if send_notification_email(user['email'], available_seats):
            conn.execute('''
                UPDATE waiting_queue SET notified = 1, notified_at = datetime('now') WHERE id = ?
            ''', (user['id'],))
            conn.commit()
    
    conn.close()

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
    
    # 检查车位是否配置了凭证
    if not account['authorization_token'] or not account['account_id']:
        conn.close()
        return jsonify({'error': '车位未配置凭证，无法发送邀请'}), 400
    
    # 调用 ChatGPT Team API 发送邀请
    try:
        result = send_team_invite(account['account_id'], account['authorization_token'], email)
        
        if not result['ok']:
            conn.close()
            return jsonify({'error': f'发送邀请失败: {result["body"]}'}), 400
        
        # 邀请发送成功，标记邀请码已使用
        conn.execute('''
            UPDATE invite_codes 
            SET used = 1, used_email = ?, used_at = datetime('now'), team_account_id = ?, user_id = ?
            WHERE code = ?
        ''', (email, final_team_id, user_id, code))
        # 标记用户已使用邀请
        conn.execute('UPDATE users SET has_used = 1 WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        
        # 同步车位状态
        try:
            sync_single_account(final_team_id, account['authorization_token'], account['account_id'])
        except:
            pass
        
        return jsonify({'status': 'ok', 'message': '邀请已发送，请查收邮件'})
    except Exception as e:
        conn.close()
        return jsonify({'error': f'发送邀请失败: {str(e)}'}), 500

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
        import threading
        threading.Thread(target=lambda: sync_single_account(new_id, authorization_token, account_id), daemon=True).start()
    
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
    return jsonify({'results': results})

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
    return jsonify({'codes': [dict(r) for r in rows]})

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
        except sqlite3.IntegrityError:
            continue
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
    return jsonify({'users': [dict(r) for r in rows]})

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
        'queue': [dict(r) for r in rows],
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

# ========== 后台自动同步 ==========

def background_sync():
    """后台线程：定时同步所有车账号状态"""
    while True:
        time.sleep(SYNC_INTERVAL)
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            accounts = conn.execute(
                'SELECT * FROM team_accounts WHERE enabled = 1 AND authorization_token IS NOT NULL AND account_id IS NOT NULL'
            ).fetchall()
            
            total_available = 0
            for acc in accounts:
                try:
                    data = fetch_team_status(acc['account_id'], acc['authorization_token'])
                    conn.execute('''
                        UPDATE team_accounts SET seats_in_use = ?, seats_entitled = ?, pending_invites = ?, active_until = ?, last_sync = datetime('now')
                        WHERE id = ?
                    ''', (data['seats_in_use'], data['seats_entitled'], data.get('pending_invites', 0), data.get('active_until'), acc['id']))
                    # 计算可用空位
                    available = data['seats_entitled'] - data['seats_in_use'] - data.get('pending_invites', 0)
                    if available > 0:
                        total_available += available
                except Exception as e:
                    print(f"[同步失败] {acc['name']}: {e}")
            
            conn.commit()
            conn.close()
            
            # 有空位时通知排队用户
            if total_available > 0:
                notify_waiting_users(total_available)
        except Exception as e:
            print(f"[后台同步错误] {e}")

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
