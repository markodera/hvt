from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("authentication", "0002_alter_auditlog_event_type_alter_auditlog_success"),
    ]

    operations = [
        migrations.AlterField(
            model_name="auditlog",
            name="event_type",
            field=models.CharField(
                choices=[
                    ("user.login", "User Login"),
                    ("user.logout", "User Logout"),
                    ("user.register", "User Registration"),
                    ("login.failed", "Login Failed"),
                    ("password.reset.request", "Password Reset Requested"),
                    ("password.reset.complete", "Password Reset Completed"),
                    ("password.changed", "Password Changed"),
                    ("email.verified", "Email Verified"),
                    ("email.verification.sent", "Verification Email Sent"),
                    ("email.verification.failed", "Verification Email Failed"),
                    ("social.login", "Social Login"),
                    ("social.connected", "Social Account Connected"),
                    ("social.disconnected", "Social Account disconnected"),
                    ("api_key.created", "API Key Created"),
                    ("api_key.revoked", "API Key Revoked"),
                    ("api_key.used", "API Key Used"),
                    ("user.created", "User Created"),
                    ("user.updated", "User Updated"),
                    ("user.deleted", "User Deleted"),
                    ("user.role.changed", "User Role Changed"),
                    ("org.created", "Organization Created"),
                    ("org.updated", "Organization Updated"),
                    ("org.member.added", "Member Added to Organization"),
                    ("org.member.removed", "Member Removed from Organization"),
                    ("org.invitation.created", "Organization Invitation Created"),
                    ("org.invitation.accepted", "Organization Invitation Accepted"),
                    ("org.invitation.revoked", "Organization Invitation Revoked"),
                ],
                db_index=True,
                max_length=50,
            ),
        ),
    ]
