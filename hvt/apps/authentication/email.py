from typing import Optional, Any
import resend
from django.conf import settings
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.utils import timezone
import logging


logger = logging.getLogger(__name__)


def build_email_context(context: Optional[dict] = None) -> dict:
    base_context = {
        "brand_name": "HVT",
        "brand_domain": "hvts.app",
        "frontend_url": getattr(settings, "FRONTEND_URL", "").rstrip("/"),
        "support_email": getattr(settings, "DEFAULT_FROM_EMAIL", "security@hvts.app"),
        "current_year": timezone.now().year,
    }
    if context:
        base_context.update(context)
    return base_context


def render_email_template(template_prefix: str, context: Optional[dict] = None) -> tuple[str, str, str]:
    email_context = build_email_context(context)
    subject = render_to_string(f"{template_prefix}_subject.txt", email_context).strip()
    text_body = render_to_string(f"{template_prefix}_message.txt", email_context).strip()

    try:
        html_body = render_to_string(f"{template_prefix}_message.html", email_context)
    except TemplateDoesNotExist:
        html_body = text_body.replace("\n", "<br>")

    return subject, text_body, html_body


class ResendEmailService:
    """
    Email service using Resend API for transactional emails.
    Provides a simple interface for sending emails via Resend.
    """

    def __init__(self, api_key: Optional[str] = None):
        resolved_api_key = api_key or getattr(settings, "RESEND_API_KEY", "")
        resend.api_key = resolved_api_key
        if not resolved_api_key:
            logger.warning("RESEND_API_KEY is empty; email send will likely fail")

    def send(
        self,
        *,
        to: str | list[str],
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
            "from": from_email or getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@hvt.dev"),
            "to": to if isinstance(to, list) else [to],
            "subject": subject,
            "html": html,
        }

        if text:
            params["text"] = text

        try:
            response = resend.Emails.send(params)  # type: ignore
            logger.info(
                "Resend email sent",
                extra={
                    "to": params["to"],
                    "subject": subject,
                    "from_email": params["from"],
                },
            )
            return response
        except Exception:
            logger.exception(
                "Resend API send failed",
                extra={
                    "to": params["to"],
                    "subject": subject,
                    "from_email": params["from"],
                },
            )
            raise


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
            else:
                logger.warning(
                    "Email backend returned unsuccessful send",
                    extra={"subject": message.subject, "to": message.recipients()},
                )
        return num_sent

    def _send(self, email_message: EmailMessage) -> bool:
        recipients = email_message.recipients()
        if not recipients:
            logger.warning("Email send skipped because there are no recipients")
            return False

        try:
            # Prepare from_email
            from_email = email_message.from_email or getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@hvt.dev")
            
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
                    # If we only have text, maybe we should also send it as html or Resend will accept it?
                    # The ResendEmailService expects html, so we can wrap text in <p> if html is empty.
                    if not html_content:
                        html_content = f"<p>{text_content}</p>"

            self.service.send(
                to=recipients,
                subject=email_message.subject,
                html=html_content,
                text=text_content if text_content else None,
                from_email=from_email,
            )
            return True
        except Exception:
            logger.exception(
                "Email backend send failed",
                extra={
                    "to": recipients,
                    "subject": email_message.subject,
                    "from_email": email_message.from_email,
                },
            )
            if not self.fail_silently:
                raise
            return False
