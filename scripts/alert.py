#!/usr/bin/env python3
"""SDLC 安全平台 - 邮件告警脚本。

用法：
    python3 scripts/alert.py <告警内容文件> <收件人邮箱>

环境变量（建议写入 /etc/sdlc-platform/alert.env 或 .env.local）：
    SMTP_HOST     SMTP 服务器地址（默认 smtp.vesync.com）
    SMTP_PORT     SMTP 端口（默认 25）
    SMTP_FROM     发件人地址（默认 sdlc-platform@vesync.com）
    SMTP_USER     SMTP 用户名（可选，端口 25 通常不需要）
    SMTP_PASSWORD SMTP 密码（可选）
    ALERT_LOG     邮件失败时的降级日志路径

示例（公司内网 SMTP）：
    export SMTP_HOST=mail.vesync.com
    export SMTP_FROM=sdlc-platform@vesync.com
"""
import os
import smtplib
import sys
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_alert(content_file: str, to_email: str) -> None:
    smtp_host = os.getenv("SMTP_HOST") or "smtp.vesync.com"
    smtp_port = int(os.getenv("SMTP_PORT") or "25")
    smtp_from = os.getenv("SMTP_FROM") or "sdlc-platform@vesync.com"
    smtp_user = os.getenv("SMTP_USER") or ""
    smtp_password = os.getenv("SMTP_PASSWORD") or ""

    with open(content_file, "r", encoding="utf-8") as f:
        content = f.read().strip()

    subject = f"[SDLC平台告警] 服务异常 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    body = (
        "SDLC 安全平台健康检查失败！\n\n"
        f"{content}\n\n"
        "请尽快登录服务器排查。\n"
        "- 查看服务状态：docker compose ps\n"
        "- 查看日志：tail -f server.log server_err.log\n"
        "- 重启服务：docker compose restart sdlc\n"
    )

    msg = MIMEMultipart()
    msg["From"] = smtp_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            if smtp_user and smtp_password:
                server.starttls()
                server.login(smtp_user, smtp_password)
            server.send_message(msg)
        print(f"[OK] 告警邮件已发送至 {to_email}")
    except Exception as e:
        print(f"[FAIL] 邮件发送失败: {e}")
        # 降级：写本地告警日志，供后续人工或另一个监控程序处理
        alert_log = os.getenv("ALERT_LOG", "logs/healthcheck_alert.log")
        os.makedirs(os.path.dirname(alert_log) or ".", exist_ok=True)
        with open(alert_log, "a", encoding="utf-8") as f:
            f.write(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                f"邮件发送失败 ({smtp_host}:{smtp_port}): {e}\n"
            )
        # 不退出非零码，避免被 cron 误判为脚本失败
        sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python3 scripts/alert.py <告警内容文件> <收件人邮箱>")
        sys.exit(2)
    send_alert(sys.argv[1], sys.argv[2])
