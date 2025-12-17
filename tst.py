#!/usr/bin/env python3
"""测试 Microsoft Graph API 邮件发送"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

MS_TENANT_ID = os.environ.get('MS_TENANT_ID', '')
MS_CLIENT_ID = os.environ.get('MS_CLIENT_ID', '')
MS_CLIENT_SECRET = os.environ.get('MS_CLIENT_SECRET', '')
MS_MAIL_FROM = os.environ.get('MS_MAIL_FROM', '')
APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://localhost:5000')

def get_access_token() -> str:
    """获取访问令牌"""
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

def send_test_email(to_email: str) -> bool:
    """发送测试邮件"""
    print("📧 Microsoft Graph API 配置检查:")
    print(f"   MS_TENANT_ID: {MS_TENANT_ID[:8]}... " if MS_TENANT_ID else "   MS_TENANT_ID: ❌ 未设置")
    print(f"   MS_CLIENT_ID: {MS_CLIENT_ID[:8]}... " if MS_CLIENT_ID else "   MS_CLIENT_ID: ❌ 未设置")
    print(f"   MS_CLIENT_SECRET: {'✅ 已设置' if MS_CLIENT_SECRET else '❌ 未设置'}")
    print(f"   MS_MAIL_FROM: {MS_MAIL_FROM or '❌ 未设置'}")
    print()
    
    if not MS_TENANT_ID or not MS_CLIENT_ID or not MS_CLIENT_SECRET or not MS_MAIL_FROM:
        print("❌ Microsoft Graph API 未完整配置，请检查 .env 文件")
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
        
        print("🔐 正在获取访问令牌...")
        token = get_access_token()
        print("✅ 令牌获取成功")
        
        print(f"📧 正在发送邮件到 {to_email}...")
        
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
            print(f"✅ 发送成功！请检查 {to_email} 的收件箱")
            return True
        else:
            print(f"❌ 发送失败: {resp.status_code}")
            print(f"   {resp.text}")
            return False
            
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
