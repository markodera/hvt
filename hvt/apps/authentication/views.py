from rest_framework import generics, permissions
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import hmac
import hashlib
import os
import json

from hvt.apps.users.models import User
from hvt.api.v1.serializers.users import UserSerializer


class CurrentUserView(generics.RetrieveUpdateAPIView):
    """
    GET /api/v1/auth/me - Get current authenticated user
    UPDATE /api/v1/auth/me - Update current user profile
    """
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


@csrf_exempt
def resend_webhook(request):
    """
    Handle Resend webhook events for email delivery status tracking.
    
    Verifies the webhook signature and processes events like:
    - email.delivered
    - email.bounced
    - email.complained
    - email.opened
    - email.clicked
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    # Verify signature header
    raw = request.body
    sig = request.headers.get("Resend-Signature", "")
    secret = os.getenv("RESEND_WEBHOOK_SIGNING_KEY", "")
    
    if secret:
        expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return JsonResponse({"error": "Invalid signature"}, status=403)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    
    event_type = payload.get("type", "")
    
    # Process events - extend this based on your needs
    # You can log to audit trail, update email status, trigger alerts, etc.
    if event_type == "email.bounced":
        # Handle bounce - maybe mark user email as invalid
        pass
    elif event_type == "email.delivered":
        # Handle delivery confirmation
        pass
    elif event_type == "email.complained":
        # Handle spam complaint
        pass
    
    return JsonResponse({"ok": True})