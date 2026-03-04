"""
Authentication signals for audit logging and webhook triggers.

Connects to Django/allauth signals to track authentication events
and fire webhooks on login events.
"""

import logging

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

logger = logging.getLogger(__name__)


def _get_client_ip(request):
    """Extract client IP, handling proxies."""
    if not request:
        return None
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


# ── Login ────────────────────────────────────────────────────────────

@receiver(user_logged_in)
def on_user_login(sender, request, user, **kwargs):
    """Audit log + webhook when a user logs in."""
    from hvt.apps.authentication.models import AuditLog
    from hvt.apps.organizations.webhooks import trigger_webhook_event

    org = getattr(user, "organization", None)

    AuditLog.log(
        event_type=AuditLog.EventType.USER_LOGIN,
        request=request,
        user=user,
        organization=org,
        target=user,
        event_data={
            "login_method": request.META.get("HTTP_X_LOGIN_METHOD", "credentials") if request else "unknown",
        },
        success=True,
    )

    if org:
        trigger_webhook_event(
            organization=org,
            event_type="user.login",
            payload={
                "user_id": str(user.id),
                "email": user.email,
                "login_method": request.META.get("HTTP_X_LOGIN_METHOD", "credentials") if request else "unknown",
            },
        )
    logger.debug("Login audit+webhook for user=%s", user.id)


# ── Logout ───────────────────────────────────────────────────────────

@receiver(user_logged_out)
def on_user_logout(sender, request, user, **kwargs):
    """Audit log when a user logs out."""
    from hvt.apps.authentication.models import AuditLog

    if not user:
        return

    AuditLog.log(
        event_type=AuditLog.EventType.USER_LOGOUT,
        request=request,
        user=user,
        organization=getattr(user, "organization", None),
        target=user,
        success=True,
    )
    logger.debug("Logout audit for user=%s", user.id)


# ── Login Failed ─────────────────────────────────────────────────────

@receiver(user_login_failed)
def on_login_failed(sender, credentials, request, **kwargs):
    """Audit log for failed login attempts (security tracking)."""
    from hvt.apps.authentication.models import AuditLog

    # Try to find the user to attach org context
    from hvt.apps.users.models import User
    email = credentials.get("email") or credentials.get("username", "")
    target_user = None
    org = None
    try:
        target_user = User.objects.get(email=email)
        org = target_user.organization
    except User.DoesNotExist:
        pass

    AuditLog.log(
        event_type=AuditLog.EventType.LOGIN_FAILED,
        request=request,
        user=None,  # no authenticated user on failure
        organization=org,
        target=target_user,
        event_data={
            "attempted_email": email,
            "ip_address": _get_client_ip(request),
        },
        success=False,
        error_message="Invalid credentials",
    )
    logger.warning("Failed login attempt for email=%s ip=%s", email, _get_client_ip(request))


# ── Allauth Signals ─────────────────────────────────────────────────

try:
    from allauth.account.signals import (
        password_changed,
        password_reset,
        email_confirmed,
        email_confirmation_sent,
    )
    from allauth.socialaccount.signals import (
        social_account_added,
        social_account_removed,
    )

    @receiver(password_changed)
    def on_password_changed(sender, request, user, **kwargs):
        """Audit log when user changes their password."""
        from hvt.apps.authentication.models import AuditLog

        AuditLog.log(
            event_type=AuditLog.EventType.PASSWORD_CHANGED,
            request=request,
            user=user,
            organization=getattr(user, "organization", None),
            target=user,
            success=True,
        )
        logger.debug("Password changed for user=%s", user.id)

    @receiver(password_reset)
    def on_password_reset(sender, request, user, **kwargs):
        """Audit log when user completes a password reset."""
        from hvt.apps.authentication.models import AuditLog

        AuditLog.log(
            event_type=AuditLog.EventType.PASSWORD_RESET_COMPLETE,
            request=request,
            user=user,
            organization=getattr(user, "organization", None),
            target=user,
            success=True,
        )
        logger.debug("Password reset completed for user=%s", user.id)

    @receiver(email_confirmed)
    def on_email_confirmed(sender, request, email_address, **kwargs):
        """Audit log when an email address is verified."""
        from hvt.apps.authentication.models import AuditLog

        user = email_address.user
        AuditLog.log(
            event_type=AuditLog.EventType.EMAIL_VERIFIED,
            request=request,
            user=user,
            organization=getattr(user, "organization", None),
            target=user,
            event_data={"email": email_address.email},
            success=True,
        )
        logger.debug("Email verified for user=%s email=%s", user.id, email_address.email)

    @receiver(email_confirmation_sent)
    def on_email_confirmation_sent(sender, request, confirmation, signup, **kwargs):
        """Audit log when a verification email is sent."""
        from hvt.apps.authentication.models import AuditLog

        user = confirmation.email_address.user
        AuditLog.log(
            event_type=AuditLog.EventType.EMAIL_VERIFICATION_SENT,
            request=request,
            user=user,
            organization=getattr(user, "organization", None),
            target=user,
            event_data={
                "email": confirmation.email_address.email,
                "is_signup": signup,
            },
            success=True,
        )
        logger.debug("Verification email sent for user=%s", user.id)

    @receiver(social_account_added)
    def on_social_account_added(sender, request, sociallogin, **kwargs):
        """Audit log when a social account is connected."""
        from hvt.apps.authentication.models import AuditLog

        user = sociallogin.user
        AuditLog.log(
            event_type=AuditLog.EventType.SOCIAL_CONNECTED,
            request=request,
            user=user,
            organization=getattr(user, "organization", None),
            target=user,
            event_data={
                "provider": sociallogin.account.provider,
                "uid": sociallogin.account.uid,
            },
            success=True,
        )
        logger.debug("Social account connected for user=%s provider=%s", user.id, sociallogin.account.provider)

    @receiver(social_account_removed)
    def on_social_account_removed(sender, request, socialaccount, **kwargs):
        """Audit log when a social account is disconnected."""
        from hvt.apps.authentication.models import AuditLog

        user = socialaccount.user
        AuditLog.log(
            event_type=AuditLog.EventType.SOCIAL_DISCONNECTED,
            request=request,
            user=user,
            organization=getattr(user, "organization", None),
            target=user,
            event_data={
                "provider": socialaccount.provider,
                "uid": socialaccount.uid,
            },
            success=True,
        )
        logger.debug("Social account disconnected for user=%s provider=%s", user.id, socialaccount.provider)

except ImportError:
    logger.warning("allauth signals not available — skipping password/email/social audit logging")
