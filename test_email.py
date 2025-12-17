#!/usr/bin/env python3
"""测试 SMTP 邮件发送"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.environ.get('SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 465))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_FROM = os.environ.get('SMTP_FROM', '')
SMTP_SSL = os.environ.get('SMTP_SSL', 'true').lower() == 'true'
APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://localhost:5000')

def send_test_email(to_email: str) -> bool:
    """发送测试邮件"""
    print("📧 SMTP 配置检查:")
    print(f"   SMTP_HOST: {SMTP_HOST or '❌ 未设置'}")
    print(f"   SMTP_PORT: {SMTP_PORT}")
    print(f"   SMTP_USER: {SMTP_USER or '❌ 未设置'}")
    print(f"   SMTP_PASS: {'✅ 已设置' if SMTP_PASS else '❌ 未设置'}")
    print(f"   SMTP_FROM: {SMTP_FROM or SMTP_USER}")
    print(f"   SMTP_SSL: {SMTP_SSL}")
    print()
    
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        print("❌ SMTP 未完整配置，请检查 .env 文件")
        return False
    
    try:
        # 模拟邀请码邮件
        invite_code = "TEST1234"
        team_name = "测试车位"
        
        subject = '您的 Team 邀请码（测试邮件）'
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
            <p style="color: #64748b; font-size: 13px;">邀请码有效期为 24 小时，逾期未使用将自动作废。</p>
            <hr style="margin: 20px 0; border: none; border-top: 1px solid #e5e7eb;">
            <p style="color: #94a3b8; font-size: 12px;">这是一封测试邮件，请忽略。</p>
        </div>
        '''
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = Header(subject, 'utf-8')
        msg['From'] = SMTP_FROM or SMTP_USER
        msg['To'] = to_email
        
        html_part = MIMEText(html_content, 'html', 'utf-8')
        msg.attach(html_part)
        
        print(f"📤 正在连接 {SMTP_HOST}:{SMTP_PORT}...")
        
        if SMTP_SSL:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls()
        
        print("🔐 正在登录...")
        server.login(SMTP_USER, SMTP_PASS)
        
        print(f"📧 正在发送邮件到 {to_email}...")
        server.sendmail(SMTP_USER, to_email, msg.as_string())
        server.quit()
        
        print(f"✅ 发送成功！请检查 {to_email} 的收件箱")
        return True
            
    except Exception as e:
        print(f"❌ 发送失败: {e}")
        return False

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python test_email.py <收件邮箱>")
        print("示例: python test_email.py your@email.com")
        sys.exit(1)
    
    to_email = sys.argv[1]
    send_test_email(to_email)
