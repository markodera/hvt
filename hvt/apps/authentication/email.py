from typing import Optional, Any
import resend
from django.conf import settings


class ResendEmailService:
    """
    Email service using Resend API for transactional emails.
    Provides a simple interface for sending emails via Resend.
    """

    def __init__(self, api_key: Optional[str] = None):
        resend.api_key = api_key or getattr(settings, "RESEND_API_KEY", "")

    def send(
        self,
        *,
        to: "str | list[str]",
        subject: str,
        html: str,
        from_email: Optional[str] = None,
        text: Optional[str] = None,
    ) -> Any:
        """
        Send an email using the Resend API.

        Args:
            to: Recipient email address or list of addresses
            subject: Email subject line
            html: HTML content of the email
            from_email: Sender email address (uses DEFAULT_FROM_EMAIL if not provided)
            text: Optional plain text version of the email

        Returns:
            Response from Resend API
        """
        params = {
            "from_": from_email
            or getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@hvt.dev"),
            "to": [to] if isinstance(to, str) else to,
            "subject": subject,
            "html": html,
        }

        if text:
            params["text"] = text

        return resend.Emails.send(params)  # type: ignore


from django.core.mail.backends.base import BaseEmailBackend
from django.core.mail import EmailMessage

class ResendEmailBackend(BaseEmailBackend):
    """
    A Django Email backend that uses the Resend API.
    """
    def __init__(self, fail_silently=False, **kwargs):
        super().__init__(fail_silently=fail_silently)
        self.service = ResendEmailService()

    def send_messages(self, email_messages):
        if not email_messages:
            return 0

        num_sent = 0
        for message in email_messages:
            if self._send(message):
                num_sent += 1
        return num_sent

    def _send(self, email_message: EmailMessage) -> bool:
        if not email_message.recipients():
            return False

        try:
            # Prepare from_email
            from_email = email_message.from_email or getattr(
                settings, "DEFAULT_FROM_EMAIL", "noreply@hvt.dev"
            )

            # Use html if message is multipart, otherwise use body
            html_content = ""
            text_content = ""

            alternatives = getattr(email_message, 'alternatives', [])
            if alternatives:
                for alt_content, mimetype in alternatives:
                    if mimetype == 'text/html':
                        html_content = alt_content
                text_content = email_message.body
            else:
                if email_message.content_subtype == 'html':
                    html_content = email_message.body
                else:
                    text_content = email_message.body
                    if not html_content:
                        html_content = f"<p>{text_content}</p>"

            self.service.send(
                    to=email_message.recipients(),
                    subject=email_message.subject,
                    html=html_content,
                    text=text_content if text_content else None,
                    from_email=from_email,
                )
            return True
        except Exception as e:
            if not self.fail_silently:
                raise e
            return False
