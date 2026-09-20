"""Custom role metadata must retain session isolation and untested personas."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from esx_eval_runner.assurance import _persona_coverage, build_coverage_model
from esx_eval_runner.browser import (
    _prepare_session,
    browser_adapter_for_persona,
    validate_browser_adapter,
    validate_browser_case,
)
from esx_eval_runner.cli import main
from esx_eval_runner.runner import RunnerError


def profile(persona, role, signal="Queue"):
    return {
        "label": persona.replace("-", " ").title(),
        "role": role,
        "session_state_path": f".esx/personas/{persona}.json",
        "session_bootstrap": {
            "login_path": "/login",
            "success": {"type": "wait_for_text", "value": signal},
        },
    }


def browser_config():
    return {
        "adapter": {
            "type": "browser_journey",
            "base_url": "http://127.0.0.1:3000",
            "personas": {
                "analyst": profile("analyst", "analyst"),
                "admin": profile("admin", "admin", "Settings"),
            },
        },
        "dataset": {"cases": []},
    }


def workflow_case(case_id, persona, area):
    return {
        "case_id": case_id,
        "persona": persona,
        "capability_area": area,
        "requires_auth": True,
        "expected_label": "pass",
        "input": {"journey": [
            {"type": "goto", "path": "/cases"},
            {"type": "expect_text", "value": "Investigations", "exact": True},
        ]},
    }


class PersonaRoleTests(unittest.TestCase):
    def test_existing_and_custom_role_labels_preserve_their_exact_metadata(self):
        for role in ("admin", "analyst", "read_only", "service", "soc_lead", "soc-lead", "tier_2-reviewer", "r", "r" * 64):
            with self.subTest(role=role):
                adapter = browser_config()["adapter"]
                adapter["personas"]["soc-lead"] = profile("soc-lead", role)
                original = deepcopy(adapter)
                validate_browser_adapter(adapter)
                self.assertEqual(browser_adapter_for_persona(adapter, "soc-lead")["role"], role)
                self.assertEqual(adapter, original)

    def test_unsafe_unbounded_and_non_string_roles_raise_runner_error(self):
        roles = ("", "r" * 65, "SOC_lead", "2nd-lead", "_lead", "-lead", "soc lead", "soc/lead",
                 "../admin", "admin:write", "admin\n", "admin\x00", "s\u00f3c_lead", None, True, 1, [], {})
        for role in roles:
            with self.subTest(role=role):
                adapter = browser_config()["adapter"]
                adapter["personas"]["analyst"]["role"] = role
                with self.assertRaisesRegex(RunnerError, "browser persona role"):
                    validate_browser_adapter(adapter)

    def test_custom_role_does_not_relax_session_path_or_bootstrap_validation(self):
        for state_path in ("../other.json", "/tmp/other.json", "https://example.test/session", "C:\\session.json"):
            with self.subTest(state_path=state_path):
                adapter = browser_config()["adapter"]
                adapter["personas"]["soc-lead"] = profile("soc-lead", "soc_lead")
                adapter["personas"]["soc-lead"]["session_state_path"] = state_path
                with self.assertRaisesRegex(RunnerError, "relative local path"):
                    validate_browser_adapter(adapter)
        for bootstrap in (
            {"login_path": "https://example.test/login", "success": {"type": "wait_for_text", "value": "Queue"}},
            {"login_path": "/login", "success": {"type": "click", "selector": "#grant-access"}},
        ):
            with self.subTest(bootstrap=bootstrap):
                adapter = browser_config()["adapter"]
                adapter["personas"]["soc-lead"] = profile("soc-lead", "soc_lead")
                adapter["personas"]["soc-lead"]["session_bootstrap"] = bootstrap
                with self.assertRaises(RunnerError):
                    validate_browser_adapter(adapter)

    def test_custom_role_uses_only_its_selected_persona_session(self):
        adapter = browser_config()["adapter"]
        adapter.update(
            session_state_path=".esx/default-session.json",
            auth={"login_path": "/login", "username_env": "ESX_TEST_USERNAME", "password_env": "ESX_TEST_PASSWORD",
                  "username_selector": "#email", "password_selector": "#password", "submit_selector": "#login",
                  "success": {"type": "wait_for_text", "value": "Dashboard"}},
        )
        adapter["personas"]["soc-lead"] = profile("soc-lead", "soc_lead", "Lead queue")
        original = deepcopy(adapter)
        validate_browser_adapter(adapter)
        selected = browser_adapter_for_persona(adapter, "soc-lead")
        self.assertEqual(selected["session_state_path"], ".esx/personas/soc-lead.json")
        self.assertEqual(selected["session_bootstrap"], adapter["personas"]["soc-lead"]["session_bootstrap"])
        self.assertNotIn("auth", selected)
        self.assertNotIn("personas", selected)
        self.assertEqual(browser_adapter_for_persona(adapter, "admin")["session_state_path"], ".esx/personas/admin.json")
        self.assertEqual(browser_adapter_for_persona(adapter, None)["session_state_path"], ".esx/default-session.json")
        self.assertEqual(adapter, original)

    def test_role_metadata_cannot_establish_an_authenticated_session(self):
        for role in ("soc_lead", "admin"):
            with self.subTest(role=role):
                adapter = browser_config()["adapter"]
                adapter["personas"]["soc-lead"] = profile("soc-lead", role)
                browser = Mock()
                with patch.object(Path, "is_file", return_value=False):
                    state, status, reason = _prepare_session(browser, browser_adapter_for_persona(adapter, "soc-lead"))
                self.assertIsNone(state)
                self.assertEqual((status, reason), ("interactive_auth_required", "session_bootstrap_required"))
                browser.new_context.assert_not_called()

    def test_cached_persona_session_is_validated_before_reuse(self):
        adapter = browser_config()["adapter"]
        state = {
            "cookies": [{"domain": "127.0.0.1", "name": "app"}],
            "origins": [{"origin": "http://127.0.0.1:3000", "localStorage": []}],
        }
        browser = Mock()
        context = Mock()
        page = Mock()
        page.url = "http://127.0.0.1:3000/login"
        visible_text = Mock()
        visible_text.wait_for.side_effect = AssertionError("session success signal missing")
        body = Mock()
        body.get_by_text.return_value = visible_text
        page.locator.return_value = body
        browser.new_context.return_value = context
        context.new_page.return_value = page
        with TemporaryDirectory() as directory, patch.object(Path, "cwd", return_value=Path(directory)):
            session_path = Path(directory) / ".esx" / "personas" / "analyst.json"
            session_path.parent.mkdir(parents=True)
            session_path.write_text(json.dumps(state), encoding="utf-8")
            selected = browser_adapter_for_persona(adapter, "analyst")
            state, status, reason = _prepare_session(browser, selected)
        self.assertIsNone(state)
        self.assertEqual((status, reason), ("stale_or_invalid", "assertion_failed"))
        browser.new_context.assert_called_once()
        context.close.assert_called_once()

    def test_stale_form_auth_session_refreshes_with_approved_env_credentials(self):
        adapter = {
            "base_url": "http://127.0.0.1:3000",
            "session_state_path": ".esx/default-session.json",
            "auth": {
                "login_path": "/login",
                "username_env": "ESX_TEST_USERNAME",
                "password_env": "ESX_TEST_PASSWORD",
                "username_selector": "#email",
                "password_selector": "#password",
                "submit_selector": "#login",
                "success": {"type": "wait_for_text", "value": "Dashboard"},
            },
        }
        state = {
            "cookies": [{"domain": "127.0.0.1", "name": "app"}],
            "origins": [{"origin": "http://127.0.0.1:3000", "localStorage": []}],
        }
        browser = Mock()
        stale_context, login_context = Mock(), Mock()
        stale_page, login_page = Mock(), Mock()
        stale_page.url = "http://127.0.0.1:3000/login"
        login_page.url = "http://127.0.0.1:3000/dashboard"
        stale_text = Mock()
        stale_text.wait_for.side_effect = AssertionError("expired")
        stale_locator = Mock()
        stale_locator.get_by_text.return_value = stale_text
        stale_page.locator.return_value = stale_locator
        login_text = Mock()
        login_locator = Mock()
        login_locator.get_by_text.return_value = login_text
        login_page.locator.return_value = login_locator
        login_context.storage_state.return_value = state
        stale_context.new_page.return_value = stale_page
        login_context.new_page.return_value = login_page
        browser.new_context.side_effect = [stale_context, login_context]
        with TemporaryDirectory() as directory, patch.object(Path, "cwd", return_value=Path(directory)), patch.dict("os.environ", {"ESX_TEST_USERNAME": "demo", "ESX_TEST_PASSWORD": "secret"}):
            session_path = Path(directory) / ".esx" / "default-session.json"
            session_path.parent.mkdir(parents=True)
            session_path.write_text(json.dumps(state), encoding="utf-8")
            refreshed, status, reason = _prepare_session(browser, adapter)
        self.assertEqual(status, "authenticated_this_run")
        self.assertIsNone(reason)
        self.assertEqual(refreshed["cookies"], state["cookies"])
        self.assertEqual(browser.new_context.call_count, 2)
        stale_context.close.assert_called_once()
        login_context.close.assert_called_once()

    def test_role_label_is_not_a_persona_id_or_automatic_case_binding(self):
        adapter = browser_config()["adapter"]
        adapter["personas"]["lead-account"] = profile("lead-account", "soc-lead")
        validate_browser_adapter(adapter)
        with self.assertRaisesRegex(RunnerError, "not configured"):
            browser_adapter_for_persona(adapter, "soc-lead")
        with self.assertRaisesRegex(RunnerError, "not configured"):
            validate_browser_case(workflow_case("lead-view", "soc-lead", "audit"), adapter)


class PersonaCoverageTests(unittest.TestCase):
    def test_all_configured_unused_personas_are_visible_with_zero_counts(self):
        config = browser_config()
        config["adapter"]["personas"]["soc-lead"] = profile("soc-lead", "soc_lead")
        original = deepcopy(config)
        rows = _persona_coverage(config, [])
        self.assertEqual([row["persona"] for row in rows], ["admin", "analyst", "soc-lead"])
        for row in rows:
            self.assertTrue(row["configured"])
            self.assertEqual(row["planned_case_count"], 0)
            self.assertEqual(row["executed_case_count"], 0)
            self.assertEqual(row["blocked_case_count"], 0)
            self.assertEqual(row["capability_areas"], [])
        self.assertEqual(rows[-1]["role"], "soc_lead")
        self.assertEqual(config, original)

    def test_coverage_model_retains_unused_profiles_and_separate_execution_counts(self):
        config = browser_config()
        config["adapter"]["personas"]["soc-lead"] = profile("soc-lead", "soc_lead")
        config["dataset"]["cases"] = [
            workflow_case("cases-analyst", "analyst", "case-management"),
            workflow_case("audit-analyst", "analyst", "audit"),
            workflow_case("audit-admin", "admin", "audit"),
        ]
        validate_browser_adapter(config["adapter"])
        for case in config["dataset"]["cases"]:
            validate_browser_case(case, config["adapter"])
        package = {
            "execution": {"adapter_type": "browser_journey", "case_count": 3, "browser_case_diagnostics": [
                {"case_id": "cases-analyst", "persona": "analyst", "capability_area": "case-management", "outcome": "passed"},
                {"case_id": "audit-analyst", "persona": "analyst", "capability_area": "audit", "outcome": "failed"},
                {"case_id": "audit-admin", "persona": "admin", "capability_area": "audit", "outcome": "blocked"},
            ]},
            "evaluation": {"required_dimensions": ["workflow_coverage"]},
        }
        original = deepcopy((config, package))
        coverage = build_coverage_model(package, {"workflow_coverage": {"measurement_status": "measured", "trust_status": "verified"}}, config=config)
        rows = {row["persona"]: row for row in coverage["personas"]}
        self.assertEqual(set(rows), {"analyst", "admin", "soc-lead"})
        self.assertEqual((rows["analyst"]["planned_case_count"], rows["analyst"]["executed_case_count"]), (2, 2))
        self.assertEqual(rows["analyst"]["capability_areas"], ["audit", "case_management"])
        self.assertEqual((rows["admin"]["planned_case_count"], rows["admin"]["executed_case_count"], rows["admin"]["blocked_case_count"]), (1, 0, 1))
        self.assertEqual((rows["soc-lead"]["planned_case_count"], rows["soc-lead"]["executed_case_count"]), (0, 0))
        self.assertEqual(rows["soc-lead"]["role"], "soc_lead")
        self.assertEqual((config, package), original)

    def test_implicit_and_unconfigured_observed_personas_remain_distinct(self):
        self.assertEqual(_persona_coverage(None, []), [])
        config = browser_config()
        config["dataset"]["cases"] = [workflow_case("public", "anonymous", "authentication")]
        rows = {row["persona"]: row for row in _persona_coverage(config, [
            {"persona": "anonymous", "outcome": "passed"},
            {"persona": "default", "outcome": "blocked"},
            {"persona": "unknown", "outcome": "failed"},
        ])}
        self.assertTrue(rows["anonymous"]["configured"])
        self.assertEqual(rows["anonymous"]["planned_case_count"], 1)
        self.assertEqual(rows["anonymous"]["role"], "implicit")
        self.assertTrue(rows["default"]["configured"])
        self.assertEqual(rows["default"]["blocked_case_count"], 1)
        self.assertFalse(rows["unknown"]["configured"])
        self.assertEqual(rows["unknown"]["executed_case_count"], 1)
        self.assertEqual(rows["admin"]["executed_case_count"], 0)


class PersonaCliTests(unittest.TestCase):
    def call_add(self, role, config):
        with patch("esx_eval_runner.cli.read_json", return_value=deepcopy(config)), patch("esx_eval_runner.cli._write_json") as write:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                status = main(["persona", "add", "--config", "memory-only.json", "--id", "soc-lead", "--role", role,
                               "--login-path", "/login", "--success-text", "Lead queue"])
        return status, write

    def test_cli_accepts_custom_roles_and_preserves_existing_persona_fixtures(self):
        for role in ("soc_lead", "soc-lead"):
            with self.subTest(role=role):
                config = browser_config()
                status, write = self.call_add(role, config)
                self.assertEqual(status, 0)
                write.assert_called_once()
                saved = write.call_args.args[1]
                self.assertEqual(saved["adapter"]["personas"]["soc-lead"]["role"], role)
                self.assertEqual(saved["adapter"]["personas"]["soc-lead"]["session_state_path"], ".esx/personas/soc-lead.json")
                for persona, original in config["adapter"]["personas"].items():
                    self.assertEqual(saved["adapter"]["personas"][persona], original)
                validate_browser_adapter(saved["adapter"])

    def test_cli_rejects_invalid_roles_before_writing_a_plan(self):
        for role in ("", "SOC_lead", "soc lead", "../admin", "r" * 65):
            with self.subTest(role=role):
                status, write = self.call_add(role, browser_config())
                self.assertEqual(status, 1)
                write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
