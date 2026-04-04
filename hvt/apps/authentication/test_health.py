from unittest.mock import patch

from django.test import SimpleTestCase, override_settings


@override_settings(
    ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"],
    SECURE_SSL_REDIRECT=True,
    SECURE_REDIRECT_EXEMPT=["healthz/", "readyz/"],
)
class HealthEndpointTests(SimpleTestCase):
    def test_healthz_is_not_redirected_under_ssl_redirect(self):
        response = self.client.get("/healthz/", secure=False)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_readyz_is_not_redirected_under_ssl_redirect(self):
        with patch("hvt.health._check_database"), patch("hvt.health._check_cache"):
            response = self.client.get("/readyz/", secure=False)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "status": "ok",
                "checks": {
                    "database": {"status": "ok"},
                    "cache": {"status": "ok"},
                },
            },
        )

    def test_non_exempt_paths_still_redirect_to_https(self):
        response = self.client.get("/api/v1/auth/login/", secure=False)

        self.assertEqual(response.status_code, 301)
        self.assertTrue(response["Location"].startswith("https://"))

    def test_readyz_returns_503_when_a_dependency_is_unavailable(self):
        with patch("hvt.health._check_database", side_effect=RuntimeError("db down")), patch(
            "hvt.health._check_cache"
        ):
            response = self.client.get("/readyz/", secure=False)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json(),
            {
                "status": "error",
                "checks": {
                    "database": {"status": "error"},
                    "cache": {"status": "ok"},
                },
            },
        )
