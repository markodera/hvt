"""
Unit and integration tests for Bring-Your-Own (BYO) Email Providers and Project Email Config.
"""

from unittest.mock import MagicMock, patch

from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from hvt.apps.authentication.email_providers import (
    ConsoleEmailProvider,
    EmailDeliveryError,
    PostmarkEmailProvider,
    ResendEmailProvider,
    SMTPEmailProvider,
    resolve_email_provider,
)
from hvt.apps.organizations.models import Organization, Project, ProjectEmailConfig
from hvt.apps.users.models import User


class BYOEmailProvidersUnitTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(name="Email Org", slug="email-org")
        self.project = Project.objects.create(
            organization=self.org,
            name="Email App",
            slug="email-app",
        )

    def test_console_email_provider(self):
        provider = ConsoleEmailProvider()
        result = provider.send(
            to="user@example.com",
            subject="Hello",
            html="<p>Test</p>",
            text="Test",
        )
        self.assertEqual(result["provider"], "console")
        self.assertTrue(result["simulated"])
        self.assertEqual(result["recipients"], ["user@example.com"])

    @patch("requests.post")
    def test_resend_email_provider_success(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"id": "resend-msg-123"})
        provider = ResendEmailProvider(api_key="re_test_key_123")
        result = provider.send(
            to="buyer@customer.com",
            subject="Welcome",
            html="<p>Welcome</p>",
        )

        self.assertEqual(result["id"], "resend-msg-123")
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.resend.com/emails")
        self.assertIn("Bearer re_test_key_123", kwargs["headers"]["Authorization"])
        self.assertEqual(kwargs["json"]["to"], ["buyer@customer.com"])

    @patch("requests.post")
    def test_postmark_email_provider_success(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200, json=lambda: {"MessageID": "pm-msg-456"})
        provider = PostmarkEmailProvider(api_key="pm_server_token_xyz")
        result = provider.send(
            to="client@customer.com",
            subject="Invoice",
            html="<p>Paid</p>",
        )

        self.assertEqual(result["id"], "pm-msg-456")
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://api.postmarkapp.com/email")
        self.assertEqual(kwargs["headers"]["X-Postmark-Server-Token"], "pm_server_token_xyz")

    @patch("django.core.mail.backends.smtp.EmailBackend.send_messages", return_value=1)
    def test_smtp_email_provider_success(self, mock_send):
        provider = SMTPEmailProvider(
            host="smtp.sendgrid.net",
            port=587,
            username="apikey",
            password="SG.secret_smtp_password",
            use_tls=True,
            default_from_email="noreply@app.com",
            default_from_name="App Mailer",
        )

        result = provider.send(
            to="user@target.com",
            subject="Verification",
            html="<p>Verify</p>",
        )

        self.assertEqual(result["status"], "sent")
        mock_send.assert_called_once()

    def test_resolve_email_provider_fallback_to_system_default(self):
        provider = resolve_email_provider(self.project)
        self.assertIsInstance(provider, (ConsoleEmailProvider, ResendEmailProvider))

    def test_resolve_email_provider_uses_project_email_config(self):
        ProjectEmailConfig.objects.create(
            project=self.project,
            provider=ProjectEmailConfig.Provider.POSTMARK,
            api_key="pm_custom_key_789",
            from_email="auth@custom-domain.com",
            from_name="Custom Domain Auth",
            is_active=True,
        )

        provider = resolve_email_provider(self.project)
        self.assertIsInstance(provider, PostmarkEmailProvider)
        self.assertEqual(provider.api_key, "pm_custom_key_789")
        self.assertEqual(provider.default_from_email, "auth@custom-domain.com")

    def test_project_email_config_encrypts_credentials_at_rest(self):
        config = ProjectEmailConfig.objects.create(
            project=self.project,
            provider=ProjectEmailConfig.Provider.SMTP,
            smtp_host="smtp.mailgun.org",
            smtp_username="postmaster@mailgun.org",
            smtp_password="super_secret_smtp_password",
            api_key="secret_api_key",
            aws_secret_access_key="secret_aws_key",
        )

        # In-memory access returns decrypted string
        config.refresh_from_db()
        self.assertEqual(config.smtp_password, "super_secret_smtp_password")
        self.assertEqual(config.api_key, "secret_api_key")
        self.assertEqual(config.aws_secret_access_key, "secret_aws_key")

        # Direct raw database query verifies plaintext is NOT stored
        from django.db import connection
        with connection.cursor() as cursor:
            lookup_id = config.id.hex if connection.vendor == "sqlite" else str(config.id)
            param = "%s" if connection.vendor != "sqlite" else "?"
            cursor.execute(
                f"SELECT smtp_password, api_key, aws_secret_access_key FROM project_email_configs WHERE id = {param}",
                [lookup_id],
            )
            raw_smtp, raw_api, raw_aws = cursor.fetchone()
            self.assertNotEqual(raw_smtp, "super_secret_smtp_password")
            self.assertNotEqual(raw_api, "secret_api_key")
            self.assertNotEqual(raw_aws, "secret_aws_key")
            self.assertTrue(raw_smtp.startswith("gAAAAA") or len(raw_smtp) > 32)


class ProjectEmailConfigAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.org = Organization.objects.create(name="API Org", slug="api-org")
        self.owner = User.objects.create_user(
            email="owner@org.com",
            password="StrongPassword123!",
            organization=self.org,
            role=User.Role.OWNER,
        )
        self.member = User.objects.create_user(
            email="member@org.com",
            password="StrongPassword123!",
            organization=self.org,
            role=User.Role.MEMBER,
        )
        self.project = Project.objects.create(
            organization=self.org,
            name="API Project",
            slug="api-project",
        )

    def test_get_project_email_config_creates_default(self):
        self.client.force_authenticate(user=self.owner)
        response = self.client.get(
            f"/api/v1/organizations/current/projects/{self.project.id}/email-config/"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["provider"], "system_default")
        self.assertFalse(data["has_smtp_password"])
        self.assertFalse(data["has_api_key"])

    def test_patch_project_email_config_updates_settings(self):
        self.client.force_authenticate(user=self.owner)
        response = self.client.patch(
            f"/api/v1/organizations/current/projects/{self.project.id}/email-config/",
            data={
                "provider": "postmark",
                "api_key": "pm_secret_test_key",
                "from_email": "security@customer.com",
                "from_name": "Customer Security",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["provider"], "postmark")
        self.assertEqual(data["from_email"], "security@customer.com")
        self.assertTrue(data["has_api_key"])

        config = ProjectEmailConfig.objects.get(project=self.project)
        self.assertEqual(config.api_key, "pm_secret_test_key")

    def test_patch_project_email_config_denies_non_admin(self):
        self.client.force_authenticate(user=self.member)
        response = self.client.patch(
            f"/api/v1/organizations/current/projects/{self.project.id}/email-config/",
            data={"provider": "smtp"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch("hvt.apps.authentication.email_providers.BaseEmailProvider.send")
    def test_test_email_dispatch_endpoint(self, mock_send):
        mock_send.return_value = {"status": "dispatched"}
        self.client.force_authenticate(user=self.owner)
        response = self.client.post(
            f"/api/v1/organizations/current/projects/{self.project.id}/email-config/test/",
            data={"to_email": "target@destination.com"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["status"], "success")
