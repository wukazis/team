#!/usr/bin/env python3
"""
SQLite 到 PostgreSQL 数据迁移脚本

使用方法:
1. 确保 PostgreSQL 已安装并创建好数据库
2. 设置环境变量 DATABASE_URL=postgresql://user:password@localhost:5432/team_db
3. 运行: python migrate_to_pg.py

注意: 运行前请备份 SQLite 数据库文件 (data.db)
"""

import os
import sqlite3
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

load_dotenv()

SQLITE_PATH = os.environ.get('DB_PATH', 'data.db')
PG_URL = os.environ.get('DATABASE_URL', '')

def migrate():
    if not PG_URL or not PG_URL.startswith('postgresql'):
        print("错误: 请设置 DATABASE_URL 环境变量")
        print("例如: DATABASE_URL=postgresql://user:password@localhost:5432/team_db")
        return
    
    if not os.path.exists(SQLITE_PATH):
        print(f"错误: SQLite 数据库文件不存在: {SQLITE_PATH}")
        return
    
    print(f"开始迁移: {SQLITE_PATH} -> PostgreSQL")
    
    # 连接 SQLite
    sqlite_conn = sqlite3.connect(SQLITE_PATH)
    sqlite_conn.row_factory = sqlite3.Row
    
    # 连接 PostgreSQL
    pg_conn = psycopg2.connect(PG_URL)
    pg_cursor = pg_conn.cursor()
    
    try:
        # 1. 创建表结构
        print("创建表结构...")
        pg_cursor.execute('''
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
        
        pg_cursor.execute('''
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
        
        pg_cursor.execute('''
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
        
        pg_cursor.execute('''
            CREATE TABLE IF NOT EXISTS waiting_queue (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) UNIQUE,
                email TEXT,
                notified INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT NOW(),
                notified_at TIMESTAMP
            )
        ''')
        
        pg_cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        # 创建索引
        pg_cursor.execute('CREATE INDEX IF NOT EXISTS idx_invite_codes_used ON invite_codes(used)')
        pg_cursor.execute('CREATE INDEX IF NOT EXISTS idx_invite_codes_team_used ON invite_codes(team_account_id, used)')
        pg_cursor.execute('CREATE INDEX IF NOT EXISTS idx_invite_codes_auto ON invite_codes(auto_generated, used)')
        pg_cursor.execute('CREATE INDEX IF NOT EXISTS idx_waiting_queue_notified ON waiting_queue(notified)')
        pg_cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_has_used ON users(has_used)')
        
        pg_conn.commit()
        print("表结构创建完成")
        
        # 辅助函数：安全获取列值
        def safe_get(row, key, default=None):
            try:
                val = row[key]
                return val if val is not None else default
            except (IndexError, KeyError):
                return default
        
        # 2. 迁移 team_accounts
        print("迁移 team_accounts...")
        rows = sqlite_conn.execute('SELECT * FROM team_accounts').fetchall()
        if rows:
            # 清空目标表
            pg_cursor.execute('TRUNCATE team_accounts CASCADE')
            for row in rows:
                pg_cursor.execute('''
                    INSERT INTO team_accounts (id, name, authorization_token, account_id, max_seats, seats_entitled, seats_in_use, enabled, active_until, pending_invites, last_sync, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (row['id'], row['name'], row['authorization_token'], row['account_id'], 
                      row['max_seats'], row['seats_entitled'], row['seats_in_use'], row['enabled'],
                      safe_get(row, 'active_until'), safe_get(row, 'pending_invites', 0), row['last_sync'], row['created_at']))
            # 重置序列
            pg_cursor.execute("SELECT setval('team_accounts_id_seq', (SELECT MAX(id) FROM team_accounts))")
            print(f"  迁移了 {len(rows)} 条记录")
        
        # 3. 迁移 users
        print("迁移 users...")
        rows = sqlite_conn.execute('SELECT * FROM users').fetchall()
        if rows:
            pg_cursor.execute('TRUNCATE users CASCADE')
            for row in rows:
                pg_cursor.execute('''
                    INSERT INTO users (id, username, name, avatar_template, trust_level, has_used, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ''', (row['id'], row['username'], row['name'], row['avatar_template'],
                      row['trust_level'], safe_get(row, 'has_used', 0), row['created_at'], row['updated_at']))
            print(f"  迁移了 {len(rows)} 条记录")
        
        # 4. 迁移 invite_codes
        print("迁移 invite_codes...")
        rows = sqlite_conn.execute('SELECT * FROM invite_codes').fetchall()
        if rows:
            pg_cursor.execute('TRUNCATE invite_codes CASCADE')
            for row in rows:
                pg_cursor.execute('''
                    INSERT INTO invite_codes (id, code, team_account_id, user_id, used, used_email, auto_generated, created_at, used_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (row['id'], row['code'], row['team_account_id'], row['user_id'],
                      row['used'], row['used_email'], safe_get(row, 'auto_generated', 0), row['created_at'], row['used_at']))
            pg_cursor.execute("SELECT setval('invite_codes_id_seq', (SELECT MAX(id) FROM invite_codes))")
            print(f"  迁移了 {len(rows)} 条记录")
        
        # 5. 迁移 waiting_queue
        print("迁移 waiting_queue...")
        rows = sqlite_conn.execute('SELECT * FROM waiting_queue').fetchall()
        if rows:
            pg_cursor.execute('TRUNCATE waiting_queue CASCADE')
            for row in rows:
                pg_cursor.execute('''
                    INSERT INTO waiting_queue (id, user_id, email, notified, created_at, notified_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (row['id'], row['user_id'], row['email'], row['notified'], row['created_at'], row['notified_at']))
            pg_cursor.execute("SELECT setval('waiting_queue_id_seq', (SELECT MAX(id) FROM waiting_queue))")
            print(f"  迁移了 {len(rows)} 条记录")
        
        # 6. 迁移 system_settings
        print("迁移 system_settings...")
        rows = sqlite_conn.execute('SELECT * FROM system_settings').fetchall()
        if rows:
            pg_cursor.execute('TRUNCATE system_settings')
            for row in rows:
                pg_cursor.execute('''
                    INSERT INTO system_settings (key, value) VALUES (%s, %s)
                ''', (row['key'], row['value']))
            print(f"  迁移了 {len(rows)} 条记录")
        
        pg_conn.commit()
        print("\n✅ 迁移完成!")
        print("请修改 .env 文件，确保 DATABASE_URL 已设置，然后重启服务")
        
    except Exception as e:
        pg_conn.rollback()
        print(f"\n❌ 迁移失败: {e}")
        raise
    finally:
        sqlite_conn.close()
        pg_cursor.close()
        pg_conn.close()

if __name__ == '__main__':
    migrate()
