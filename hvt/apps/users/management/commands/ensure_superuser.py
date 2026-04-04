import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create or update a superuser from environment variables."

    def handle(self, *args, **options):
        email = os.getenv("DJANGO_SUPERUSER_EMAIL", "").strip()
        password = os.getenv("DJANGO_SUPERUSER_PASSWORD", "").strip()
        first_name = os.getenv("DJANGO_SUPERUSER_FIRST_NAME", "").strip()
        last_name = os.getenv("DJANGO_SUPERUSER_LAST_NAME", "").strip()

        if not email:
            self.stdout.write(
                self.style.WARNING(
                    "DJANGO_SUPERUSER_EMAIL not set; skipping superuser bootstrap."
                )
            )
            return

        if not password:
            self.stdout.write(
                self.style.WARNING(
                    "DJANGO_SUPERUSER_PASSWORD not set; skipping superuser bootstrap."
                )
            )
            return

        user_model = get_user_model()
        user, created = user_model.objects.get_or_create(
            email=email,
            defaults={
                "is_staff": True,
                "is_superuser": True,
                "is_active": True,
                "first_name": first_name,
                "last_name": last_name,
            },
        )

        updated_fields = []
        if created:
            user.set_password(password)
            updated_fields.append("password")
        else:
            if not user.check_password(password):
                user.set_password(password)
                updated_fields.append("password")

            if not user.is_staff:
                user.is_staff = True
                updated_fields.append("is_staff")

            if not user.is_superuser:
                user.is_superuser = True
                updated_fields.append("is_superuser")

            if not user.is_active:
                user.is_active = True
                updated_fields.append("is_active")

            if first_name and user.first_name != first_name:
                user.first_name = first_name
                updated_fields.append("first_name")

            if last_name and user.last_name != last_name:
                user.last_name = last_name
                updated_fields.append("last_name")

        if created:
            user.save()
            self.stdout.write(
                self.style.SUCCESS(f"Created superuser {email}.")
            )
            return

        if updated_fields:
            user.save(update_fields=updated_fields)
            self.stdout.write(
                self.style.SUCCESS(
                    f"Updated superuser {email} ({', '.join(updated_fields)})."
                )
            )
            return

        self.stdout.write(
            self.style.SUCCESS(f"Superuser {email} already up to date.")
        )
