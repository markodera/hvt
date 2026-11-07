"""
Pluggable email providers for HVT Bring-Your-Own-Email (BYO-Email) architecture.

Supports:
- Resend (API)
- SMTP (standard Django EmailBackend connection)
- Postmark (REST API)
- Amazon SES (REST/boto3)
"""

import abc
import json
import logging
from typing import Any, Dict, List, Optional, Union

import requests
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.core.mail.backends.smtp import EmailBackend as DjangoSMTPEmailBackend
from email.utils import formataddr, parseaddr

logger = logging.getLogger(__name__)


class EmailProviderError(Exception):
    """Raised when an email delivery attempt fails."""
    pass


EmailDeliveryError = EmailProviderError


class EmailProvider(abc.ABC):
    """
    Abstract Base Class for transactional email providers.
    """

    def __init__(
        self,
        default_from_email: Optional[str] = None,
        default_from_name: Optional[str] = None,
    ):
        self.default_from_email = (default_from_email or "").strip() or None
        self.default_from_name = (default_from_name or "").strip() or None

    def _resolve_sender(
        self,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> tuple[str, str]:
        sender_email = (
            from_email
            or self.default_from_email
            or getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@notify.hvts.app")
        )
        sender_name = from_name if from_name is not None else (self.default_from_name or "")
        sender_formatted = formataddr((sender_name, sender_email)) if sender_name else sender_email
        return sender_email, sender_formatted

    @abc.abstractmethod
    def send(
        self,
        *,
        to: Union[str, List[str]],
        subject: str,
        html: str,
        text: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send an email message.

        Returns a dictionary containing delivery metadata (e.g. message ID, status).
        Raises EmailProviderError on failure.
        """
        pass


class ResendEmailProvider(EmailProvider):
    """
    Email provider for Resend API.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        default_from_email: Optional[str] = None,
        default_from_name: Optional[str] = None,
    ):
        super().__init__(default_from_email=default_from_email, default_from_name=default_from_name)
        self.api_key = api_key or getattr(settings, "RESEND_API_KEY", "")
        if not self.api_key:
            logger.warning("ResendEmailProvider initialized without an API key.")

    def send(
        self,
        *,
        to: Union[str, List[str]],
        subject: str,
        html: str,
        text: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.api_key:
            raise EmailProviderError("Resend API key is not configured.")

        recipients = [to] if isinstance(to, str) else list(to)
        _, sender = self._resolve_sender(from_email, from_name)

        payload: Dict[str, Any] = {
            "from": sender,
            "to": recipients,
            "subject": subject,
            "html": html,
        }
        if text:
            payload["text"] = text

        try:
            import resend
            resend.api_key = self.api_key
            response = resend.Emails.send(payload)  # type: ignore
            msg_id = getattr(response, "id", None) or (response.get("id") if isinstance(response, dict) else str(response))
            return {"provider": "resend", "id": msg_id, "status": "sent"}
        except Exception as exc:
            logger.warning("Resend send failed via SDK, attempting REST fallback: %s", exc)
            try:
                res = requests.post(
                    "https://api.resend.com/emails",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=10,
                )
                if not (200 <= res.status_code < 300):
                    raise EmailProviderError(f"Resend HTTP {res.status_code}: {res.text}")
                data = res.json()
                return {"provider": "resend", "id": data.get("id", ""), "status": "sent"}
            except Exception as http_exc:
                raise EmailProviderError(f"Resend delivery failed: {http_exc}") from http_exc


class SMTPEmailProvider(EmailProvider):
    """
    Email provider using standard SMTP connection.
    Compatible with Mailgun, SendGrid, Amazon SES SMTP, Postfix, and Mailtrap.
    """

    def __init__(
        self,
        host: str,
        port: int = 587,
        username: str = "",
        password: str = "",
        use_tls: bool = True,
        use_ssl: bool = False,
        timeout: int = 10,
        default_from_email: Optional[str] = None,
        default_from_name: Optional[str] = None,
    ):
        super().__init__(default_from_email=default_from_email, default_from_name=default_from_name)
        self.host = host
        self.port = int(port or 587)
        self.username = username
        self.password = password
        self.use_tls = bool(use_tls)
        self.use_ssl = bool(use_ssl)
        self.timeout = timeout

    def send(
        self,
        *,
        to: Union[str, List[str]],
        subject: str,
        html: str,
        text: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        recipients = [to] if isinstance(to, str) else list(to)
        _, sender = self._resolve_sender(from_email, from_name)

        body_text = text or html
        msg = EmailMultiAlternatives(
            subject=subject,
            body=body_text,
            from_email=sender,
            to=recipients,
        )
        if html and body_text != html:
            msg.attach_alternative(html, "text/html")
        elif html:
            msg.content_subtype = "html"

        try:
            backend = DjangoSMTPEmailBackend(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                use_tls=self.use_tls,
                use_ssl=self.use_ssl,
                timeout=self.timeout,
                fail_silently=False,
            )
            sent_count = backend.send_messages([msg])
            if sent_count == 0:
                raise EmailProviderError("SMTP server accepted 0 messages.")
            return {"provider": "smtp", "status": "sent", "count": sent_count}
        except Exception as exc:
            logger.exception("SMTP email send failed: %s", exc)
            raise EmailProviderError(f"SMTP delivery failed: {exc}") from exc


class PostmarkEmailProvider(EmailProvider):
    """
    Email provider for Postmark Server API.
    """

    def __init__(
        self,
        server_token: str = "",
        default_from_email: Optional[str] = None,
        default_from_name: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        super().__init__(default_from_email=default_from_email, default_from_name=default_from_name)
        token = (server_token or api_key or "").strip()
        self.server_token = token
        self.api_key = token
        if not self.server_token:
            logger.warning("PostmarkEmailProvider initialized without a server token.")

    def send(
        self,
        *,
        to: Union[str, List[str]],
        subject: str,
        html: str,
        text: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.server_token:
            raise EmailProviderError("Postmark server token is not configured.")

        recipients = [to] if isinstance(to, str) else list(to)
        _, sender = self._resolve_sender(from_email, from_name)

        payload: Dict[str, Any] = {
            "From": sender,
            "To": ", ".join(recipients),
            "Subject": subject,
            "HtmlBody": html,
        }
        if text:
            payload["TextBody"] = text

        try:
            res = requests.post(
                "https://api.postmarkapp.com/email",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "X-Postmark-Server-Token": self.server_token,
                },
                json=payload,
                timeout=10,
            )
            if not (200 <= res.status_code < 300):
                raise EmailProviderError(f"Postmark HTTP {res.status_code}: {res.text}")
            data = res.json()
            return {
                "provider": "postmark",
                "id": str(data.get("MessageID", "")),
                "status": "sent",
            }
        except Exception as exc:
            logger.exception("Postmark email send failed: %s", exc)
            raise EmailProviderError(f"Postmark delivery failed: {exc}") from exc


class SESEmailProvider(EmailProvider):
    """
    Email provider for Amazon Simple Email Service (SES).
    Uses boto3 if available.
    """

    def __init__(
        self,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_region: str = "us-east-1",
        default_from_email: Optional[str] = None,
        default_from_name: Optional[str] = None,
    ):
        super().__init__(default_from_email=default_from_email, default_from_name=default_from_name)
        self.aws_access_key_id = (aws_access_key_id or "").strip()
        self.aws_secret_access_key = (aws_secret_access_key or "").strip()
        self.aws_region = (aws_region or "us-east-1").strip()

    def send(
        self,
        *,
        to: Union[str, List[str]],
        subject: str,
        html: str,
        text: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.aws_access_key_id or not self.aws_secret_access_key:
            raise EmailProviderError("AWS SES credentials are incomplete.")

        recipients = [to] if isinstance(to, str) else list(to)
        _, sender = self._resolve_sender(from_email, from_name)

        try:
            import boto3
            client = boto3.client(
                "ses",
                region_name=self.aws_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
            )
            body: Dict[str, Any] = {"Html": {"Charset": "UTF-8", "Data": html}}
            if text:
                body["Text"] = {"Charset": "UTF-8", "Data": text}

            response = client.send_email(
                Source=sender,
                Destination={"ToAddresses": recipients},
                Message={
                    "Subject": {"Charset": "UTF-8", "Data": subject},
                    "Body": body,
                },
            )
            return {
                "provider": "ses",
                "id": str(response.get("MessageId", "")),
                "status": "sent",
            }
        except ImportError:
            logger.warning("boto3 not installed; SES provider requires boto3 package.")
            raise EmailProviderError("boto3 is required for Amazon SES provider.")
        except Exception as exc:
            logger.exception("AWS SES send failed: %s", exc)
            raise EmailProviderError(f"AWS SES delivery failed: {exc}") from exc



class ConsoleEmailProvider(EmailProvider):
    def send(
        self,
        *,
        to: Union[str, List[str]],
        subject: str,
        html: str,
        text: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        recipients = [to] if isinstance(to, str) else list(to)
        logger.info("[ConsoleEmailProvider] Sending to %s | Subject: %s", recipients, subject)
        return {
            "provider": "console",
            "recipients": recipients,
            "subject": subject,
            "simulated": True,
        }


BaseEmailProvider = EmailProvider
AWSSESEmailProvider = SESEmailProvider

def build_email_provider(
    provider_type: str,
    credentials: Dict[str, Any],
    from_email: Optional[str] = None,
    from_name: Optional[str] = None,
) -> EmailProvider:
    """
    Factory creating an EmailProvider instance from provider type and credentials dict.
    """
    ptype = (provider_type or "resend").lower().strip()
    creds = credentials or {}

    if ptype in ("resend", "system_default"):
        return ResendEmailProvider(
            api_key=creds.get("api_key"),
            default_from_email=from_email,
            default_from_name=from_name,
        )
    elif ptype == "smtp":
        return SMTPEmailProvider(
            host=creds.get("host", ""),
            port=int(creds.get("port") or 587),
            username=creds.get("username", ""),
            password=creds.get("password", ""),
            use_tls=creds.get("use_tls", True),
            use_ssl=creds.get("use_ssl", False),
            default_from_email=from_email,
            default_from_name=from_name,
        )
    elif ptype == "postmark":
        return PostmarkEmailProvider(
            server_token=creds.get("server_token", ""),
            default_from_email=from_email,
            default_from_name=from_name,
        )
    elif ptype == "ses":
        return SESEmailProvider(
            aws_access_key_id=creds.get("aws_access_key_id", ""),
            aws_secret_access_key=creds.get("aws_secret_access_key", ""),
            aws_region=creds.get("aws_region", "us-east-1"),
            default_from_email=from_email,
            default_from_name=from_name,
        )
    else:
        raise ValueError(f"Unsupported email provider type: {provider_type}")


def get_email_provider_for_project(project=None) -> EmailProvider:
    """
    Resolve the active EmailProvider for a given project.
    Falls back to system-level Resend provider if project has no active custom config.
    """
    if project is not None:
        try:
            config = getattr(project, "email_config", None)
            if config is not None and config.is_active:
                creds = config.get_credentials()
                return build_email_provider(
                    config.provider,
                    creds,
                    from_email=config.from_email,
                    from_name=config.from_name,
                )
        except Exception as exc:
            logger.warning("Failed to resolve project email config; falling back to system provider: %s", exc)

    import sys
    if getattr(settings, "TESTING", False) or "test" in sys.argv:
        return ConsoleEmailProvider()

    return ResendEmailProvider()


resolve_email_provider = get_email_provider_for_project
