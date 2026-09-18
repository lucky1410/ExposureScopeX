"""Exercise the local setup handler without opening sockets or running targets."""

from contextlib import redirect_stdout
import io
import json
from types import SimpleNamespace
from threading import RLock
import unittest
from unittest.mock import Mock, patch

from esx_eval_runner import setup
from esx_eval_runner.runner import RunnerError


class ApplicationSetupRouteTests(unittest.TestCase):
    def setUp(self):
        self.port = 54321
        captured = []
        self.lock_depth = 0
        owner = self

        class ReviewLock:
            def __init__(self):
                self.lock = RLock()

            def __enter__(self):
                self.lock.acquire()
                owner.lock_depth += 1

            def __exit__(self, *args):
                owner.lock_depth -= 1
                self.lock.release()

        def server_factory(address, handler):
            self.assertEqual(address, ("127.0.0.1", 0))
            captured.append(handler)
            return Mock(server_port=self.port)

        with patch.object(setup, "ThreadingHTTPServer", side_effect=server_factory), \
                patch("esx_eval_runner.release_setup._SETUP_LOCK", ReviewLock()), \
                patch.object(setup.secrets, "token_urlsafe", return_value="test-setup-token"), \
                patch.object(setup.webbrowser, "open") as browser, redirect_stdout(io.StringIO()):
            setup.serve_setup(application=True)
        browser.assert_called_once_with(f"http://127.0.0.1:{self.port}/application")
        self.handler_type = captured[0]

    def request(self, method, path, payload=None, *, host=None, token="test-setup-token", raw=None):
        handler = self.handler_type.__new__(self.handler_type)
        handler.server = SimpleNamespace(server_port=self.port)
        handler.path = path
        body = raw if raw is not None else json.dumps(payload or {}).encode("utf-8")
        handler.headers = {"Host": host or f"127.0.0.1:{self.port}", "Content-Length": str(len(body))}
        if token is not None:
            handler.headers["X-ESX-Setup-Token"] = token
        handler.rfile = io.BytesIO(body)
        handler.wfile = io.BytesIO()
        statuses = []
        handler.send_response = statuses.append
        handler.send_error = statuses.append
        handler.send_header = Mock()
        handler.end_headers = Mock()
        getattr(handler, "do_" + method)()
        return statuses[-1], handler.wfile.getvalue()

    def test_page_contains_local_guided_form_and_loopback_host_is_required(self):
        status, body = self.request("GET", "/application")
        self.assertEqual(status, 200)
        self.assertIn(b"PRE-D Application Release Setup", body)
        self.assertIn(b"test-setup-token", body)
        for host in ("attacker.invalid", "127.0.0.1", "localhost:54322"):
            with self.subTest(host=host):
                status, body = self.request("GET", "/application", host=host)
                self.assertEqual(status, 403)
                self.assertNotIn(b"test-setup-token", body)

    def test_both_application_routes_require_csrf_and_exact_local_host(self):
        with patch("esx_eval_runner.release_setup.preview_application") as preview, \
                patch("esx_eval_runner.release_setup.create_application") as create:
            for path in ("/api/application/preview", "/api/application/create"):
                for host, token in ((None, None), (None, "wrong-token"), ("attacker.invalid", "test-setup-token")):
                    with self.subTest(path=path, host=host, token=token):
                        status, _ = self.request("POST", path, host=host, token=token)
                        self.assertEqual(status, 403)
            preview.assert_not_called()
            create.assert_not_called()

    def test_preview_and_create_dispatch_only_explicit_route(self):
        values = {"review_sha256": "reviewed-fingerprint"}
        with patch("esx_eval_runner.release_setup.preview_application", return_value={"status": "preview"}) as preview, \
                patch("esx_eval_runner.release_setup.create_application", return_value={"status": "created"}) as create:
            status, body = self.request("POST", "/api/application/preview", values)
            self.assertEqual((status, json.loads(body)["status"]), (200, "preview"))
            create.assert_not_called()
            self.assertEqual(preview.call_args.args[0]["review_sha256"], values["review_sha256"])
            status, body = self.request("POST", "/api/application/create", values)
            self.assertEqual((status, json.loads(body)["status"]), (201, "created"))
            create.assert_called_once()
            preview.assert_called_once()

    def test_invalid_body_rejected_before_setup_functions(self):
        with patch("esx_eval_runner.release_setup.preview_application") as preview:
            for body in (b"[]", b"{broken", b"", b"x" * 1_048_577):
                with self.subTest(length=len(body)):
                    status, _ = self.request("POST", "/api/application/preview", raw=body)
                    self.assertEqual(status, 400)
            preview.assert_not_called()

    def test_setup_validation_error_is_visible_and_os_details_are_not(self):
        with patch("esx_eval_runner.release_setup.create_application", side_effect=RunnerError("Preview the changed plan again")):
            status, body = self.request("POST", "/api/application/create")
            self.assertEqual(status, 400)
            self.assertIn(b"Preview the changed plan again", body)
        with patch("esx_eval_runner.release_setup.create_application", side_effect=OSError("private-path-sentinel")):
            status, body = self.request("POST", "/api/application/create")
            self.assertEqual(status, 400)
            self.assertNotIn(b"private-path-sentinel", body)

    def test_all_directory_sensitive_routes_share_the_review_lock(self):
        def page(*args):
            self.assertEqual(self.lock_depth, 1)
            return "page"

        def discovery(*args):
            self.assertEqual(self.lock_depth, 1)
            return {"status": "local"}

        with patch.object(setup, "_pred_local_setup_html", side_effect=page), \
                patch.object(setup, "_guided_setup_html_with_evidence", side_effect=page), \
                patch("esx_eval_runner.release_setup.application_setup_html", side_effect=page), \
                patch.object(setup, "discover_repository", side_effect=discovery):
            for path in ("/", "/browser", "/application"):
                self.assertEqual(self.request("GET", path)[0], 200)
                self.assertEqual(self.lock_depth, 0)
            self.assertEqual(self.request("POST", "/api/discover")[0], 200)
            self.assertEqual(self.lock_depth, 0)


if __name__ == "__main__":
    unittest.main()
