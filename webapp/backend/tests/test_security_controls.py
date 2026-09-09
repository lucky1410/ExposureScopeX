import socket
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pydantic import ValidationError as PydanticValidationError

from app.config import Settings
from app.security import create_access_token, decode_token
from app.api.v1.reports import _generate_pdf_report
from app.services.celery_app import celery_app, nuclei_template_update_task
from app.services.validation import ValidationError, resolve_and_check, validate_public_url


class OutboundRequestSecurityTests(unittest.TestCase):
    def test_loopback_url_is_rejected(self):
        with self.assertRaises(ValidationError):
            validate_public_url("http://127.0.0.1/admin")

    def test_url_credentials_are_rejected(self):
        with self.assertRaises(ValidationError):
            validate_public_url("https://user:secret@example.com/")

    def test_mixed_public_private_dns_is_rejected(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ]
        with patch("app.services.validation.socket.getaddrinfo", return_value=answers):
            with self.assertRaises(ValidationError):
                resolve_and_check("example.com")


class ProductionConfigurationTests(unittest.TestCase):
    def test_production_rejects_insecure_defaults(self):
        with self.assertRaises(PydanticValidationError):
            Settings(ENVIRONMENT="production", _env_file=None)

    def test_production_accepts_required_security_settings(self):
        settings = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="a" * 64,
            SESSION_COOKIE_SECURE=True,
            REDIS_PASSWORD="b" * 32,
            REDIS_URL=f"redis://:{'b' * 32}@redis:6379/0",
            BACKEND_CORS_ORIGINS=["https://exposurescopex.example"],
            METRICS_BEARER_TOKEN="c" * 64,
            _env_file=None,
        )
        self.assertEqual(settings.ENVIRONMENT, "production")


class SecurityPrimitiveTests(unittest.TestCase):
    def test_access_token_round_trip_and_tamper_rejection(self):
        token = create_access_token({"sub": "user-1", "org_id": "org-1"})
        self.assertEqual(decode_token(token)["sub"], "user-1")
        header, payload, signature = token.split(".")
        replacement = "a" if signature[0] != "a" else "b"
        self.assertIsNone(decode_token(f"{header}.{payload}.{replacement}{signature[1:]}"))

    def test_pdf_generation_does_not_require_html_renderer(self):
        assessment = SimpleNamespace(
            name="Security <review>",
            target="example.com",
            status="completed",
        )
        content = _generate_pdf_report(
            assessment,
            [],
            [],
            {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        )
        self.assertTrue(content.startswith(b"%PDF-"))
        self.assertGreater(len(content), 500)


class SecurityMaintenanceTests(unittest.TestCase):
    def test_nuclei_template_update_is_scheduled_daily(self):
        schedule = celery_app.conf.beat_schedule["nuclei-templates-daily"]
        self.assertEqual(
            schedule["task"],
            "app.services.celery_app.nuclei_template_update_task",
        )
        self.assertEqual(schedule["schedule"], 86400)
        self.assertEqual(schedule["options"]["queue"], "default")

    @patch("subprocess.run")
    def test_nuclei_template_update_uses_fixed_command(self, run):
        run.return_value = SimpleNamespace(returncode=0, stdout="updated", stderr="")
        result = nuclei_template_update_task.run()
        self.assertEqual(result["status"], "completed")
        run.assert_called_once_with(
            ["/app/worker/entrypoint.sh", "update-templates"],
            capture_output=True,
            check=False,
            text=True,
            timeout=1750,
        )
