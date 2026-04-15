import os
import smtplib
from email.message import EmailMessage
import time

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Credentials loaded from .env when configured
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@neopolis.com")

# =====================================================================
# DEBOUNCE / THROTTLING ENGINE (Tasks 2)
# =====================================================================
# Tracks the last time an alert was fired per project to prevent 50,000 emails a minute.
_last_alert_timestamps = {}
ALERT_COOLDOWN_SECONDS = 300 # 5 minutes

def send_critical_alert_email(category: str, project_name: str, log_details: str):
    """
    Sends a beautifully formatted HTML email to the admin when an anomaly is detected.
    This function gets executed by FastAPI's BackgroundTasks so it doesn't block the API response.
    Includes a 5-minute debounce lock to prevent spam.
    """
    global _last_alert_timestamps
    
    current_time = time.time()
    last_sent = _last_alert_timestamps.get(project_name, 0)
    
    if (current_time - last_sent) < ALERT_COOLDOWN_SECONDS:
        # Throttle active: Do not send redundant emails yet
        return

    # Lock updated instantly
    _last_alert_timestamps[project_name] = current_time
    if not SMTP_SERVER or not SMTP_USERNAME or not SMTP_PASSWORD:
        # If SMTP is not actively configured yet, we simulate the email output to the console!
        print("\n" + "="*60)
        print("🚨 [ML TRIGGER SIMULATION] 🚨")
        print(f"[Email Server]: Would have successfully sent an HTML email alert.")
        print(f"[To]: {ADMIN_EMAIL}")
        print(f"[Project]: {project_name}")
        print(f"[Log Output]:\n{log_details}")
        print("-" * 60)
        print("💡 NOTE: Set SMTP_SERVER, SMTP_USERNAME, and SMTP_PASSWORD in your .env file to enable real emails!")
        print("="*60 + "\n")
        return

    msg = EmailMessage()
    msg['Subject'] = f"🚨 CRITICAL ANOMALY ALERT: {project_name} 🚨"
    msg['From'] = SMTP_USERNAME
    msg['To'] = ADMIN_EMAIL

    # Rich HTML Email Template Design (Matching Frontend Aesthetics)
    html_content = f"""
    <html>
    <body style="font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; padding: 30px 10px; background-color: #060b28; margin: 0;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #0d1238; border: 1px solid #1a2555; border-radius: 12px; overflow: hidden; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.2);">
            
            <div style="padding: 24px; border-bottom: 1px solid rgba(26, 37, 85, 0.8);">
                <div style="display: block; margin-bottom: 4px;">
                    <span style="display: inline-block; padding: 4px 10px; background-color: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); color: #ef4444; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em;">
                        Action Required
                    </span>
                </div>
                <h2 style="color: #ffffff; margin: 12px 0 0 0; font-size: 20px; font-weight: 600; letter-spacing: -0.02em;">
                    Critical Anomaly Detected
                </h2>
                <p style="color: #7a84b3; font-size: 14px; margin: 6px 0 0 0;">
                    Project: <strong style="color: #ffffff; font-weight: 600;">{project_name}</strong>
                </p>
            </div>
            
            <div style="padding: 24px;">
                <p style="font-size: 14px; color: #7a84b3; line-height: 1.6; margin-top: 0;">
                    The machine learning anomaly detection engine has flagged highly suspicious real-time system behavior. Immediate review is recommended.
                </p>
                
                <div style="background-color: #060b28; border: 1px solid #1a2555; padding: 16px; border-radius: 8px; margin: 24px 0;">
                    <p style="margin: 0 0 12px 0; color: #4a5490; font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.1em;">Log Diagnostics</p>
                    <pre style="white-space: pre-wrap; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace; color: #ef4444; margin: 0; font-size: 13px; line-height: 1.5; word-break: break-all;">{log_details}</pre>
                </div>
                
                <div style="margin-top: 32px;">
                    <a href="#" style="display: inline-block; background-color: #131b4d; color: #ffffff; border: 1px solid #1a2555; padding: 10px 18px; border-radius: 6px; font-size: 13px; font-weight: 600; text-decoration: none; transition: background-color 0.2s;">
                        Open Master Dashboard
                    </a>
                </div>
            </div>
            
            <div style="background-color: rgba(19, 27, 77, 0.4); border-top: 1px solid #1a2555; padding: 16px 24px; text-align: center;">
                <p style="color: #4a5490; font-size: 12px; margin: 0;">
                    Automatically generated by the Logging Inference Engine
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Fallback for old clients
    msg.set_content(f"A critical anomaly was detected in {project_name}:\n\n{log_details}")
    # Set the HTML version
    msg.add_alternative(html_content, subtype='html')

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
            print(f"[Notifications: Success] Sent critical alert email for '{project_name}' to {ADMIN_EMAIL}")
    except Exception as e:
        print(f"[Notifications: Error] Failed to send critical alert email: {e}")
