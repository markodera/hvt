from unittest.mock import patch
from django.test import TestCase
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.test.utils import override_settings

from hvt.apps.authentication.email import (
    ResendEmailBackend,
    ResendEmailService,
    build_email_context,
    render_email_template,
)


class ResendEmailBackendTest(TestCase):
    """
    Test suite for ResendEmailBackend and ResendEmailService
    Provides small, isolated tests so we don't have to run the whole test suite.
    """

    def setUp(self):
        self.backend = ResendEmailBackend()
        
    @patch('resend.Emails.send')
    def test_send_basic_text_email(self, mock_send):
        """Test sending a simple text email"""
        # Mock the resend API response
        mock_send.return_value = {"id": "re_12345"}
        
        email = EmailMessage(
            subject='Hello from HVT',
            body='This is a basic text email.',
            from_email='noreply@test.hvt.dev',
            to=['user@example.com']
        )
        
        # Send using our Resend backend
        num_sent = self.backend.send_messages([email])
        
        self.assertEqual(num_sent, 1)
        mock_send.assert_called_once()
        
        # Verify payload sent to resend
        call_args = mock_send.call_args[0][0]  # dict passed to resend.Emails.send
        
        self.assertEqual(call_args['to'], ['user@example.com'])
        self.assertEqual(call_args['subject'], 'Hello from HVT')
        self.assertEqual(call_args['from'], 'noreply@test.hvt.dev')
        self.assertEqual(call_args['text'], 'This is a basic text email.')
        self.assertEqual(call_args['html'], '<p>This is a basic text email.</p>')

    @patch('resend.Emails.send')
    def test_send_html_email(self, mock_send):
        """Test sending an email with just HTML content"""
        mock_send.return_value = {"id": "re_67890"}
        
        email = EmailMessage(
            subject='Hello HTML',
            body='<h1>This is HTML</h1>',
            from_email='noreply@test.hvt.dev',
            to=['user@example.com']
        )
        # Indicate this is an HTML email
        email.content_subtype = "html"
        
        num_sent = self.backend.send_messages([email])
        self.assertEqual(num_sent, 1)
        
        call_args = mock_send.call_args[0][0]
        self.assertEqual(call_args['html'], '<h1>This is HTML</h1>')
        self.assertNotIn('text', call_args)

    @patch('resend.Emails.send')
    def test_send_multipart_email(self, mock_send):
        """Test sending a multipart email (Text + HTML)"""
        mock_send.return_value = {"id": "re_multipart"}
        
        email = EmailMultiAlternatives(
            subject='Hello Multipart',
            body='This is the plain text version.',
            from_email='noreply@test.hvt.dev',
            to=['user@example.com']
        )
        email.attach_alternative("<p>This is the HTML version.</p>", "text/html")
        
        num_sent = self.backend.send_messages([email])
        self.assertEqual(num_sent, 1)
        
        call_args = mock_send.call_args[0][0]
        self.assertEqual(call_args['text'], 'This is the plain text version.')
        self.assertEqual(call_args['html'], '<p>This is the HTML version.</p>')
        
    @patch('resend.Emails.send')
    def test_fail_silently_behavior(self, mock_send):
        """Test that exceptions are properly handled based on fail_silently"""
        # Force the mock to raise an exception
        mock_send.side_effect = Exception("Resend API Error")
        
        email = EmailMessage(
            subject='Will Fail',
            body='Error trigger',
            to=['user@example.com']
        )
        
        # Test loud (fail_silently=False)
        backend_loud = ResendEmailBackend(fail_silently=False)
        with self.assertRaises(Exception) as context:
            backend_loud.send_messages([email])
        self.assertTrue("Resend API Error" in str(context.exception))
        
        # Test silent (fail_silently=True)
        backend_silent = ResendEmailBackend(fail_silently=True)
        num_sent = backend_silent.send_messages([email])
        
        # Should return 0 messages sent instead of throwing
        self.assertEqual(num_sent, 0)

    @patch('resend.Emails.send')
    def test_send_to_all_recipients(self, mock_send):
        """Ensure backend forwards all recipients to Resend."""
        mock_send.return_value = {"id": "re_all_recipients"}

        email = EmailMessage(
            subject="Group notice",
            body="Sent to many",
            to=["user1@example.com", "user2@example.com"],
        )

        num_sent = self.backend.send_messages([email])
        self.assertEqual(num_sent, 1)

        call_args = mock_send.call_args[0][0]
        self.assertEqual(call_args["to"], ["user1@example.com", "user2@example.com"])

    @patch('resend.Emails.send')
    @override_settings(DEFAULT_FROM_EMAIL="fallback@example.com")
    def test_default_from_email_comes_from_settings(self, mock_send):
        """DEFAULT_FROM_EMAIL should come from Django settings when missing."""
        mock_send.return_value = {"id": "re_default_from"}

        email = EmailMessage(
            subject="Fallback sender",
            body="No explicit sender",
            to=["user@example.com"],
        )

        num_sent = self.backend.send_messages([email])
        self.assertEqual(num_sent, 1)

        call_args = mock_send.call_args[0][0]
        self.assertEqual(call_args["from"], "fallback@example.com")

    def test_build_email_context_runtime_project_sets_app_fields(self):
        """Runtime project name should drive user-facing app text in templates."""
        context = build_email_context({"project_name": "Acme Store"})

        self.assertEqual(context["project_name"], "Acme Store")
        self.assertEqual(context["product_name"], "Acme Store")
        self.assertEqual(context["account_name"], "Acme Store account")
        self.assertIn("on behalf of Acme Store", context["brand_name"])

    def test_render_email_template_uses_project_name_in_subject(self):
        """Verification subject should use project name during runtime auth flows."""
        subject, text_body, _ = render_email_template(
            "account/email/email_confirmation",
            {"project_name": "Acme Store"},
        )

        self.assertEqual(subject, "Verify your email for Acme Store")
        self.assertIn("Acme Store account", text_body)

    def test_password_reset_template_uses_project_name_when_available(self):
        """Password reset copy should use runtime app name when project context exists."""
        subject, text_body, _ = render_email_template(
            "account/email/password_reset_key",
            {
                "project_name": "Acme Store",
                "password_reset_url": "https://app.example/reset/token",
            },
        )

        self.assertEqual(subject, "Reset your Acme Store password")
        self.assertIn("Acme Store account", text_body)

    def test_invitation_template_uses_project_name_when_available(self):
        """Invitation copy should highlight project/app context when provided."""
        subject, text_body, _ = render_email_template(
            "organizations/email/invitation",
            {
                "organization_name": "Acme Org",
                "role_label": "Member",
                "project_name": "Acme Store",
                "accept_url": "https://app.example/invite?token=abc",
                "invitee_email": "dev@example.com",
                "expires_at_display": "April 08, 2026 at 12:00 UTC",
                "app_role_labels": ["buyer"],
                "invited_by_email": "owner@example.com",
            },
        )

        self.assertEqual(subject, "You're invited to join Acme Org for Acme Store")
        self.assertIn("for Acme Store as a Member", text_body)
