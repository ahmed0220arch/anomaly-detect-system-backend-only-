import os
import smtplib
from email.message import EmailMessage

# Credentials loaded from .env when configured
SMTP_SERVER = os.getenv("SMTP_SERVER", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@neopolis.com")

def send_critical_alert_email(project_name: str, log_details: str):
    """
    Sends a beautifully formatted HTML email to the admin when an anomaly is detected.
    This function gets executed by FastAPI's BackgroundTasks so it doesn't block the API response.
    """
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

    # Rich HTML Email Template Design
    html_content = f"""
    <html>
    <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; background-color: #f8f9fa;">
        <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; border-top: 5px solid #dc3545; box-shadow: 0 8px 16px rgba(0,0,0,0.08);">
            
            <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom: 20px;">
                <tr>
                    <td style="vertical-align: middle;">
                        <span style="font-size: 28px; background: #fff1f2; color: #e11d48; padding: 10px; border-radius: 8px; font-weight: bold;">🚨</span>
                    </td>
                    <td style="vertical-align: middle; padding-left: 15px; width: 100%;">
                        <h2 style="color: #111827; margin: 0; font-size: 22px;">Critical Anomaly Detected</h2>
                    </td>
                </tr>
            </table>
            
            <p style="font-size: 16px; color: #4b5563; line-height: 1.6;">
                The machine learning anomaly detection engine has flagged highly suspicious real-time activity in your project <strong>{project_name}</strong>.
            </p>
            
            <div style="background-color: #1f2937; padding: 20px; border-radius: 8px; margin: 25px 0;">
                <h4 style="margin-top: 0; color: #9ca3af; font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em;">Trace & Log Details:</h4>
                <pre style="white-space: pre-wrap; font-family: 'Fira Code', 'Consolas', monospace; color: #f87171; margin: 0; font-size: 14px; line-height: 1.5;">{log_details}</pre>
            </div>
            
            <p style="color: #6b7280; font-size: 14px; margin-top: 30px; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 20px;">
                Please secure your environment and check your Master Dashboard immediately for full diagnostics.
            </p>
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
