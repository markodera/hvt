from typing import Optional, Any
import resend
import os


class ResendEmailService:
    """
    Email service using Resend API for transactional emails.
    Provides a simple interface for sending emails via Resend.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        resend.api_key = api_key or os.getenv("RESEND_API_KEY", "")

    def send(
        self,
        *,
        to: str,
        subject: str,
        html: str,
        from_email: Optional[str] = None,
        text: Optional[str] = None,
    ) -> Any:
        """
        Send an email using the Resend API.
        
        Args:
            to: Recipient email address
            subject: Email subject line
            html: HTML content of the email
            from_email: Sender email address (uses DEFAULT_FROM_EMAIL if not provided)
            text: Optional plain text version of the email
            
        Returns:
            Response from Resend API
        """
        params = {
            "from_": from_email or os.getenv("DEFAULT_FROM_EMAIL", "noreply@yourdomain.com"),
            "to": [to],
            "subject": subject,
            "html": html,
        }
        
        if text:
            params["text"] = text
        
        return resend.Emails.send(params)