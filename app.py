#!/usr/bin/env python3
"""
简化版邀请码系统 - 支持多车账号
运行: python app.py
访问: http://localhost:5000
"""

import os
import sqlite3
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session
from dotenv import load_dotenv
import requests

load_dotenv()

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

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
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
            last_sync TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        
        CREATE TABLE IF NOT EXISTS invite_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            team_account_id INTEGER REFERENCES team_accounts(id),
            used INTEGER DEFAULT 0,
            used_email TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            used_at TEXT
        );
    ''')
    conn.commit()
    conn.close()

def generate_code():
    return secrets.token_urlsafe(8).upper()[:12]

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

# ========== 公开 API ==========

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'time': datetime.now().isoformat()})

@app.route('/api/team-accounts/status')
def team_accounts_status():
    """获取所有车位状态（公开）- 使用缓存数据，不实时请求API"""
    conn = get_db()
    accounts = conn.execute('''
        SELECT id, name, max_seats, seats_entitled, seats_in_use, enabled, last_sync, created_at
        FROM team_accounts WHERE enabled = 1
        ORDER BY id ASC
    ''').fetchall()
    
    result = []
    for acc in accounts:
        # 本地邀请码统计（未使用的）
        local_pending = conn.execute('''
            SELECT COUNT(*) FROM invite_codes 
            WHERE team_account_id = ? AND used = 0
        ''', (acc['id'],)).fetchone()[0]
        
        result.append({
            'id': acc['id'],
            'name': acc['name'],
            'maxSeats': acc['max_seats'],
            'enabled': bool(acc['enabled']),
            'seatsInUse': acc['seats_in_use'],
            'pendingInvites': local_pending,
            'seatsEntitled': acc['seats_entitled'],
            'lastSync': acc['last_sync'],
            'createdAt': acc['created_at']
        })
    
    conn.close()
    return jsonify({'accounts': result})

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
def use_invite():
    """使用邀请码 - 发送真实的 ChatGPT Team 邀请"""
    data = request.json or {}
    code = (data.get('code') or '').strip().upper()
    email = (data.get('email') or '').strip().lower()
    team_account_id = data.get('teamAccountId')
    
    if not code:
        return jsonify({'error': '请输入邀请码'}), 400
    if not email or '@' not in email:
        return jsonify({'error': '请输入有效邮箱'}), 400
    
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
            SET used = 1, used_email = ?, used_at = datetime('now'), team_account_id = ?
            WHERE code = ?
        ''', (email, final_team_id, code))
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'ok', 'message': '邀请已发送，请查收邮件'})
    except Exception as e:
        conn.close()
        return jsonify({'error': f'发送邀请失败: {str(e)}'}), 500

# ========== 管理员 API ==========

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.json or {}
    if data.get('password') == ADMIN_PASSWORD:
        session['is_admin'] = True
        return jsonify({'status': 'ok'})
    return jsonify({'error': '密码错误'}), 401

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
        SELECT id, name, authorization_token, account_id, max_seats, seats_entitled, seats_in_use, enabled, last_sync, created_at
        FROM team_accounts ORDER BY id ASC
    ''').fetchall()
    
    result = []
    for acc in accounts:
        pending = conn.execute('''
            SELECT COUNT(*) FROM invite_codes 
            WHERE team_account_id = ? AND used = 0
        ''', (acc['id'],)).fetchone()[0]
        
        result.append({
            'id': acc['id'],
            'name': acc['name'],
            'authorizationToken': acc['authorization_token'] or '',
            'accountId': acc['account_id'] or '',
            'maxSeats': acc['max_seats'],
            'enabled': bool(acc['enabled']),
            'seatsInUse': acc['seats_in_use'],
            'pendingInvites': pending,
            'seatsEntitled': acc['seats_entitled'],
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
    
    if not name:
        return jsonify({'error': '请输入车位名称'}), 400
    
    conn = get_db()
    cursor = conn.execute(
        'INSERT INTO team_accounts (name, authorization_token, account_id, max_seats, seats_entitled) VALUES (?, ?, ?, ?, ?)',
        (name, authorization_token, account_id, max_seats, max_seats)
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
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
    
    conn = get_db()
    conn.execute('''
        UPDATE team_accounts SET name = ?, authorization_token = ?, account_id = ?, max_seats = ?, enabled = ?
        WHERE id = ?
    ''', (name, authorization_token, acc_id, max_seats, enabled, account_id))
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
            UPDATE team_accounts SET seats_in_use = ?, seats_entitled = ?, last_sync = datetime('now')
            WHERE id = ?
        ''', (data['seats_in_use'], data['seats_entitled'], account_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'ok',
            'seatsInUse': data['seats_in_use'],
            'seatsEntitled': data['seats_entitled'],
            'pendingInvites': data['pending_invites']
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
                UPDATE team_accounts SET seats_in_use = ?, seats_entitled = ?, last_sync = datetime('now')
                WHERE id = ?
            ''', (data['seats_in_use'], data['seats_entitled'], acc['id']))
            
            results.append({
                'id': acc['id'], 
                'name': acc['name'], 
                'seatsInUse': data['seats_in_use'],
                'seatsEntitled': data['seats_entitled']
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
        SELECT c.*, t.name as team_name
        FROM invite_codes c
        LEFT JOIN team_accounts t ON c.team_account_id = t.id
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

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    print(f"启动服务: http://localhost:{port}")
    print(f"管理后台: http://localhost:{port}/admin")
    if ADMIN_PASSWORD == 'admin123':
        print(f"⚠️  使用默认管理密码，请在 .env 中设置 ADMIN_PASSWORD")
    app.run(host='0.0.0.0', port=port, debug=debug)
