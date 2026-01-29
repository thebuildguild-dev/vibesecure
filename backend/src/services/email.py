import logging
import resend

from src.core.config import settings
from src.core.models import get_risk_label

logger = logging.getLogger(__name__)

def get_risk_color(risk_level: str) -> str:
    colors = {
        "Critical": "#DC2626", 
        "High": "#EA580C",     
        "Medium": "#D97706",   
        "Low": "#059669",      
        "Secure": "#059669"    
    }
    return colors.get(risk_level, "#6B7280")

def send_scan_complete_email(to_email: str, scan_url: str, risk_score: int, scan_id: int) -> None:
    try:
        resend.api_key = settings.resend_api_key
        
        risk_level = get_risk_label(risk_score)
        risk_color = get_risk_color(risk_level)
        dashboard_url = f"{settings.frontend_url}/scan/{scan_id}"
        
        subject = f"Security Scan Complete: {risk_level} Risk Detected"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
            <title>VibeSecure Scan Results</title>
            <style>
                /* Base styles */
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f3f4f6; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 40px 20px; }}
                .card {{ background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); overflow: hidden; }}
                .header {{ background-color: #111827; padding: 24px; text-align: center; }}
                .logo {{ color: #ffffff; font-size: 20px; font-weight: 700; text-decoration: none; letter-spacing: 0.5px; }}
                .content {{ padding: 32px; }}
                .badge {{ display: inline-block; padding: 6px 12px; border-radius: 9999px; font-size: 14px; font-weight: 600; color: #ffffff; background-color: {risk_color}; }}
                .score-large {{ font-size: 36px; font-weight: 800; color: #1f2937; margin: 16px 0 8px 0; }}
                .info-row {{ border-bottom: 1px solid #e5e7eb; padding: 12px 0; }}
                .info-label {{ color: #6b7280; font-size: 14px; }}
                .info-value {{ color: #111827; font-weight: 500; word-break: break-all; }}
                .button {{ display: inline-block; background-color: #4f46e5; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600; margin-top: 24px; text-align: center; }}
                .footer {{ text-align: center; margin-top: 24px; color: #6b7280; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="header">
                        <div class="logo">VibeSecure</div>
                    </div>
                    <div class="content">
                        <h2 style="margin: 0 0 16px 0; color: #111827; font-size: 20px;">Scan Analysis Complete</h2>
                        <p style="margin: 0 0 24px 0; color: #4b5563; line-height: 1.5;">
                            We have finished analyzing the URL you submitted. Here is the summary of our findings.
                        </p>
                        
                        <div style="text-align: center; margin-bottom: 24px; background-color: #f9fafb; padding: 20px; border-radius: 8px;">
                            <span class="badge">{risk_level} Risk</span>
                            <div class="score-large">{risk_score}/100</div>
                            <div style="color: #6b7280; font-size: 14px;">Security Score</div>
                        </div>

                        <div class="info-row">
                            <div class="info-label">Target URL</div>
                            <div class="info-value"><a href="{scan_url}" style="color: #4f46e5; text-decoration: none;">{scan_url}</a></div>
                        </div>
                        
                        <div style="text-align: center;">
                            <a href="{dashboard_url}"
                                style="
                                    display:inline-block;
                                    background-color:#4f46e5;
                                    color:#ffffff !important;
                                    padding:14px 28px;
                                    font-size:16px;
                                    font-weight:600;
                                    border-radius:8px;
                                    text-decoration:none;
                                    margin-top:20px;
                                    ">
                                View Full Report
                            </a>
                        </div>
                    </div>
                </div>
                <div class="footer">
                    &copy; 2026 VibeSecure. All rights reserved.<br>
                    Automated security notification.
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
VibeSecure Scan Complete
------------------------

Target URL: {scan_url}
Risk Level: {risk_level}
Security Score: {risk_score}/100

View full report: {dashboard_url}

------------------------
VibeSecure Automated System
        """
        
        params = {
            "from": settings.email_from,
            "to": [to_email],
            "subject": subject,
            "html": html_body,
            "text": text_body
        }
        
        response = resend.Emails.send(params)
        logger.info(f"Scan completion email sent to {to_email} (ID: {response.get('id', 'unknown')})")
        
    except Exception as e:
        logger.error(f"Failed to send scan completion email to {to_email}: {str(e)}")