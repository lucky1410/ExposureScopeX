"""Application setup uses real local plans without executing or inventing cases."""

from contextlib import ExitStack, redirect_stdout, redirect_stderr
from copy import deepcopy
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import re
import shlex
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from esx_eval_runner import release_setup
from esx_eval_runner.cli import main
from esx_eval_runner.release import validate_manifest
from esx_eval_runner.release_execution import preflight_all_modules
from esx_eval_runner.release_setup import application_setup_html, create_application, preview_application
from esx_eval_runner.runner import RunnerError, sha256
from test_release import adapter_config, write


def create_reviewed(values):
    preview = preview_application(values)
    return create_application({**values, "review_sha256": preview["review_sha256"]})


def workflow_config(*, persona="default", assertion=True):
    config = adapter_config(None)
    config["evaluation"].update(agent_id="workflow-engine", required_dimensions=["workflow_coverage"])
    config["adapter"] = {"type": "browser_journey", "base_url": "http://127.0.0.1:9876"}
    steps = [{"type": "goto", "path": "/"}]
    if assertion:
        steps.append({"type": "assert_path", "path": "/"})
    config["dataset"]["cases"] = [{"case_id": "existing-journey", "persona": persona,
                                    "input": {"journey": steps}, "expected_label": "pass"}]
    return config


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attributes = {}
        self.script = ""
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        values = dict(attrs)
        if "id" in values:
            self.attributes[values["id"]] = values
        if tag == "script":
            self.in_script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.script += data


class ApplicationSetupTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.plan = self.root / "existing plan.json"
        self.config = adapter_config(None)
        write(self.plan, self.config)
        self.values = {
            "application_id": "sample-app", "subject_version": "release-4",
            "directory": str(self.root / "new release"), "inventory_complete": True,
            "confirm_plan": True,
            "modules": [{"id": "decisions", "profile": "decision", "personas": [], "depends_on": [],
                         "plans": [{"path": str(self.plan), "mode": "read_only"}]}],
        }

    def bind_all(self):
        module = preview_application(self.values)["modules"][0]
        suite = module["plans"][0]
        self.values["modules"][0]["requirement_bindings"] = {
            objective["id"]: [{"suite_id": suite["suite_id"],
                               "case_ids": [suite["cases"][0]["case_id"]],
                               "assertion": "Compare the existing fixture decision with its reviewed label."}]
            for objective in module["objectives"]
        }

    def test_preview_is_read_only_and_returns_only_real_case_metadata(self):
        self.config["dataset"]["cases"][0]["input"]["secret"] = "input-secret-sentinel"
        self.config["adapter"]["command"].append("command-secret-sentinel")
        write(self.plan, self.config)
        original = deepcopy(self.values)
        result = preview_application(self.values)
        self.assertEqual(self.values, original)
        self.assertFalse(Path(self.values["directory"]).exists())
        self.assertEqual(list(self.root.iterdir()), [self.plan])
        self.assertFalse(result["target_calls_made"])
        self.assertEqual(result["manifest"], validate_manifest(result["manifest"]))
        suite = result["manifest"]["modules"][0]["suites"][0]
        self.assertEqual(suite["id"], "decisions-decision-1")
        self.assertEqual(suite["execution_policy"]["config_sha256"], sha256(self.config))
        cases = result["modules"][0]["plans"][0]["cases"]
        self.assertEqual(cases, [{"case_id": case["case_id"], "persona": None,
                                  "expected_label": case["expected_label"]}
                                 for case in self.config["dataset"]["cases"]])
        self.assertTrue(all(not item["bindings"] for item in result["modules"][0]["objectives"]))
        self.assertEqual(result["preflight"]["status"], "blocked")
        self.assertEqual({issue["code"] for issue in result["preflight"]["issues"]}, {"requirement_unbound"})
        self.assertEqual(result["review_scope"]["summary"]["blocked"], 1)
        self.assertEqual(result["review_scope"]["modules"][0]["review_status"], "blocked")
        self.assertEqual(result["review_scope"]["modules"][0]["executable_methods"][0]["status"], "blocked")
        self.assertEqual(result["preflight_display"]["issues"][0]["summary"], "A reviewed objective still has no real case binding.")
        for secret in ("input-secret-sentinel", "command-secret-sentinel", "example_index", "import json,sys"):
            self.assertNotIn(secret, json.dumps(result))

    def test_manual_review_note_is_preserved_and_shown_in_scope_preview(self):
        self.values["modules"][0]["review_methods"] = [{
            "label": "Runbook review",
            "status": "inspected",
            "summary": "Reviewed rollback notes and dependency owners.",
            "evidence_pointer": "notes/release-review.md",
        }]
        preview = preview_application(self.values)
        scope_module = preview["review_scope"]["modules"][0]
        self.assertEqual(scope_module["review_status"], "blocked")
        self.assertEqual(scope_module["manual_methods"][0]["label"], "Runbook review")
        self.assertEqual(scope_module["manual_methods"][0]["status"], "inspected")
        self.assertIn('"review_methods"', preview["review_scope"]["manifest_json"])
        self.bind_all()
        self.values["modules"][0]["review_methods"] = [{
            "label": "Runbook review",
            "status": "inspected",
            "summary": "Reviewed rollback notes and dependency owners.",
            "evidence_pointer": "notes/release-review.md",
        }]
        created = create_reviewed(self.values)
        self.assertEqual(created["manifest"]["modules"][0]["review_methods"][0]["label"], "Runbook review")
        self.assertEqual(created["manifest"]["modules"][0]["review_methods"][0]["status"], "inspected")

    def test_preview_and_create_never_execute_adapters_or_network_or_import_app(self):
        self.bind_all()
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(target, side_effect=AssertionError(target))) for target in (
                "esx_eval_runner.cli.run_command", "esx_eval_runner.runner.build_package",
                "esx_eval_runner.runner._invoke_command_adapter", "esx_eval_runner.runner._invoke_http_json_target",
                "esx_eval_runner.browser.invoke_browser_journeys", "subprocess.run", "subprocess.Popen",
                "socket.create_connection", "socket.socket.connect", "urllib.request.urlopen",
                "importlib.import_module",
            )]
            preview_application(self.values)
            result = create_reviewed(self.values)
            for guard in guards:
                guard.assert_not_called()
        self.assertEqual(result["preflight"]["status"], "ready")
        self.assertFalse(result["target_calls_made"])
        self.assertEqual({path.name for path in Path(result["directory"]).iterdir()}, {"release.json", "setup-summary.json"})

    def test_create_preserves_reviewed_bindings_and_matches_real_preflight(self):
        self.bind_all()
        result = create_reviewed(self.values)
        manifest_path = Path(result["manifest_path"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        summary = json.loads(Path(result["summary_path"]).read_text(encoding="utf-8"))
        self.assertEqual(summary, result)
        self.assertEqual(manifest, result["manifest"])
        self.assertEqual(summary["status"], "created")
        preflight, prepared, _ = preflight_all_modules(manifest, manifest_path)
        self.assertEqual(summary["preflight"], preflight)
        self.assertEqual(preflight["status"], "ready")
        self.assertEqual(preflight["planned_case_count"], 20)
        self.assertEqual(set(prepared), {"decisions-decision-1"})
        for objective in manifest["modules"][0]["test_requirements"]:
            self.assertEqual(objective["bindings"], self.values["modules"][0]["requirement_bindings"][objective["id"]])
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            exit_code = main(["release", "preflight", "--manifest", str(manifest_path),
                              "--out", str(self.root / "cli-preflight.json")])
        self.assertEqual(exit_code, 0)

    def test_unbound_drafts_can_be_created_but_are_explicitly_blocked(self):
        result = create_reviewed(self.values)
        self.assertEqual(result["preflight"]["status"], "blocked")
        self.assertEqual(len(result["preflight"]["issues"]), 3)
        self.assertTrue(all(not objective["bindings"] for objective in result["modules"][0]["objectives"]))

    def test_invalid_ids_profiles_shapes_and_dependencies(self):
        mutations = [
            ("application_id", "Bad ID"), ("application_id", "a" * 81), ("subject_version", ""),
            ("inventory_complete", "true"), ("modules", []), ("modules", [None]),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                values = deepcopy(self.values)
                values[field] = value
                with self.assertRaises(RunnerError):
                    preview_application(values)
        for field, value in (("id", "../oops"), ("profile", "ai"), ("profile", []),
                             ("personas", "admin"), ("personas", ["admin"]),
                             ("depends_on", ["unknown"]), ("depends_on", ["decisions"]),
                             ("depends_on", ["x", "x"]), ("plans", {}),
                             ("requirement_bindings", {"invented-objective": []})):
            with self.subTest(field=field, value=value):
                values = deepcopy(self.values)
                values["modules"][0][field] = value
                with self.assertRaises(RunnerError):
                    preview_application(values)
        self.assertFalse(Path(self.values["directory"]).exists())

    def test_wrong_identity_or_invalid_explicit_plan_rejected_before_writes(self):
        for field in ("project_key", "subject_version"):
            with self.subTest(field=field):
                config = deepcopy(self.config)
                config["evaluation"][field] = "other-secret-identity"
                write(self.plan, config)
                with self.assertRaisesRegex(RunnerError, "project_key, subject_version") as caught:
                    create_application(self.values)
                self.assertNotIn("other-secret-identity", str(caught.exception))
        config = deepcopy(self.config)
        config["adapter"]["type"] = "unsupported"
        write(self.plan, config)
        with self.assertRaisesRegex(RunnerError, "adapter type"):
            preview_application(self.values)
        self.values["modules"][0]["plans"][0]["path"] = str(self.root / "missing.json")
        with self.assertRaisesRegex(RunnerError, "cannot validate"):
            create_application(self.values)
        self.assertFalse(Path(self.values["directory"]).exists())

    def test_missing_plans_and_missing_required_kind_stay_gaps(self):
        self.values["modules"][0]["profile"] = "mixed"
        result = preview_application(self.values)
        self.assertEqual({row["kind"] for row in result["modules"][0]["plans"]}, {"decision"})
        missing = [issue for issue in result["preflight"]["issues"] if issue["code"] == "required_kind_missing"]
        self.assertEqual(len(missing), 1)
        self.assertIn("workflow", missing[0]["action"])
        self.values["modules"][0]["plans"] = []
        result = create_reviewed(self.values)
        self.assertEqual(result["modules"][0]["plans"], [])
        self.assertEqual(result["preflight"]["planned_case_count"], 0)
        self.assertIn("module_has_no_plans", {issue["code"] for issue in result["preflight"]["issues"]})
        self.assertTrue(all(not objective["bindings"] for objective in result["modules"][0]["objectives"]))

    def test_create_requires_literal_confirmation_and_inventory_review(self):
        for key in ("confirm_plan", "inventory_complete"):
            for value in (False, None, "true", 1):
                with self.subTest(key=key, value=value):
                    values = deepcopy(self.values)
                    values[key] = value
                    with self.assertRaisesRegex(RunnerError, key):
                        create_application(values)
        self.values["inventory_complete"] = False
        preview = preview_application(self.values)
        self.assertIn("inventory_unconfirmed", {issue["code"] for issue in preview["preflight"]["issues"]})
        self.assertFalse(Path(self.values["directory"]).exists())

    def test_reviewed_modes_and_nonempty_isolation_note_required(self):
        for mode, note in ((None, None), ("write", None), ([], None), ("isolated_write", None),
                           ("isolated_write", " "), ("read_only", "\nsecret")):
            with self.subTest(mode=mode, note=note):
                values = deepcopy(self.values)
                plan = values["modules"][0]["plans"][0]
                plan["mode"] = mode
                if note is not None:
                    plan["isolation_note"] = note
                with self.assertRaises(RunnerError):
                    create_application(values)
        self.values["modules"][0]["plans"][0].update(mode="isolated_write", isolation_note="Disposable tenant; external delivery disabled.")
        result = create_reviewed(self.values)
        approval = result["manifest"]["modules"][0]["suites"][0]["execution_policy"]
        self.assertEqual(approval["mode"], "isolated_write")
        self.assertEqual(approval["isolation_note"], "Disposable tenant; external delivery disabled.")

    def test_wrong_bindings_rejected_before_directory_or_file_creation(self):
        self.bind_all()
        for field, value in (("suite_id", "made-up-suite"), ("case_ids", ["made-up-case"]),
                             ("case_ids", ["case-000", "case-000"]), ("case_ids", []),
                             ("assertion", "")):
            with self.subTest(field=field):
                values = deepcopy(self.values)
                values["modules"][0]["requirement_bindings"]["decision-happy-path"][0][field] = value
                with patch.object(Path, "mkdir", side_effect=AssertionError("write before validation")) as mkdir:
                    with self.assertRaises(RunnerError):
                        create_application(values)
                    mkdir.assert_not_called()
        self.assertFalse(Path(self.values["directory"]).exists())

    def test_workflow_persona_and_explicit_assertion_must_match_real_cases(self):
        module = self.values["modules"][0]
        module.update(profile="workflow", personas=["anonymous"])
        write(self.plan, workflow_config())
        self.bind_all()
        with self.assertRaisesRegex(RunnerError, "requirement_persona_mismatch"):
            create_application(self.values)
        write(self.plan, workflow_config(persona="anonymous", assertion=False))
        with self.assertRaisesRegex(RunnerError, "explicit success assertion"):
            create_application(self.values)
        self.assertFalse(Path(self.values["directory"]).exists())
        write(self.plan, workflow_config(persona="anonymous"))
        result = create_reviewed(self.values)
        self.assertEqual(result["preflight"]["status"], "ready")
        self.assertEqual(result["modules"][0]["plans"][0]["cases"],
                         [{"case_id": "existing-journey", "persona": "anonymous", "expected_label": "pass"}])

    def test_preview_cannot_request_execution_or_accept_navigation_only_workflows(self):
        for key in ("run", "execute", "command"):
            values = {**self.values, key: True}
            with self.assertRaisesRegex(RunnerError, "supported fields"):
                preview_application(values)
        self.values["modules"][0]["profile"] = "workflow"
        write(self.plan, workflow_config(assertion=False))
        with patch("esx_eval_runner.browser.invoke_browser_journeys") as invoke:
            with self.assertRaisesRegex(RunnerError, "explicit success assertion"):
                preview_application(self.values)
            invoke.assert_not_called()

    def test_metric_guidance_preserves_exact_source_dimensions_without_enabling_metrics(self):
        dimensions = ["classification", "confidence", "rag", "groundedness", "trajectory", "tool_use"]
        self.config["adapter"]["type"] = "command_json_v2"
        self.config["evaluation"]["required_dimensions"] = dimensions
        write(self.plan, self.config)
        original = self.plan.read_bytes()
        result = create_reviewed(self.values)
        self.assertEqual(result["modules"][0]["plans"][0]["required_dimensions"], dimensions)
        self.assertEqual(self.plan.read_bytes(), original)
        self.assertEqual(len(result["metric_presets"]), 3)
        self.assertIn("configured judge", result["metric_presets"][-1]["guidance"])
        self.assertIn("adds no judge or metrics", result["metric_presets"][-1]["guidance"])

    def test_preview_surfaces_decision_and_workflow_coverage_advisories(self):
        result = preview_application(self.values)
        self.assertEqual(
            {item["code"] for item in result["preflight_display"]["advisories"]},
            {"baseline_dimension_unexercised", "population_context_missing"},
        )
        self.values["modules"][0]["profile"] = "workflow"
        write(self.plan, workflow_config())
        workflow_preview = preview_application(self.values)
        self.assertEqual(
            workflow_preview["modules"][0]["plans"][0]["workflow_signal_strength"]["route_signal_only_count"],
            1,
        )
        self.assertEqual(
            {item["code"] for item in workflow_preview["preflight_display"]["advisories"]},
            {"workflow_route_only_signal"},
        )

    def test_no_overwrite_of_existing_empty_directory_nonempty_directory_or_file(self):
        for name in ("empty", "occupied", "file"):
            with self.subTest(name=name):
                target = self.root / name
                if name == "file":
                    target.write_text("keep", encoding="utf-8")
                else:
                    target.mkdir()
                    if name == "occupied":
                        (target / "release.json").write_text("keep", encoding="utf-8")
                self.values["directory"] = str(target)
                with self.assertRaisesRegex(RunnerError, "existing target"):
                    create_application(self.values)
                if name == "empty":
                    self.assertEqual(list(target.iterdir()), [])
                else:
                    self.assertEqual((target if name == "file" else target / "release.json").read_text(), "keep")

    def test_exclusive_file_creation_does_not_overwrite_or_delete_racing_file(self):
        original_open = Path.open

        def race(path, mode="r", *args, **kwargs):
            if path.name == "release.json" and mode == "x":
                with original_open(path, "w", encoding="utf-8") as stream:
                    stream.write("another writer")
            return original_open(path, mode, *args, **kwargs)

        with patch.object(Path, "open", race):
            with self.assertRaisesRegex(RunnerError, "Nothing was overwritten or deleted"):
                create_reviewed(self.values)
        self.assertEqual((Path(self.values["directory"]) / "release.json").read_text(), "another writer")

    def test_network_paths_rejected_before_local_plan_validation(self):
        for path in ("https://example.invalid/plan.json", "//server/share/plan.json", "\\\\server\\share\\plan.json"):
            with self.subTest(path=path):
                self.values["modules"][0]["plans"][0]["path"] = path
                with patch.object(release_setup, "load_plan") as load:
                    with self.assertRaisesRegex(RunnerError, "local filesystem path"):
                        preview_application(self.values)
                    load.assert_not_called()

    def test_create_requires_a_matching_review_snapshot(self):
        self.bind_all()
        with self.assertRaisesRegex(RunnerError, "no preview was confirmed"):
            create_application(self.values)
        self.values["review_sha256"] = preview_application(self.values)["review_sha256"]
        self.config["dataset"]["cases"][0]["input"]["changed"] = True
        write(self.plan, self.config)
        with self.assertRaisesRegex(RunnerError, "changed"):
            create_application(self.values)
        self.assertFalse(Path(self.values["directory"]).exists())
        self.values["review_sha256"] = preview_application(self.values)["review_sha256"]
        self.values["modules"][0]["requirement_bindings"]["decision-happy-path"][0]["assertion"] = "Different assertion."
        with self.assertRaisesRegex(RunnerError, "changed"):
            create_application(self.values)
        self.assertFalse(Path(self.values["directory"]).exists())
        result = create_reviewed(self.values)
        self.assertEqual(result["status"], "created")

    def test_changing_destination_or_scope_invalidates_review(self):
        original = preview_application(self.values)["review_sha256"]
        for change in ("directory", "scope"):
            with self.subTest(change=change):
                values = deepcopy(self.values)
                values["review_sha256"] = original
                if change == "directory":
                    values["directory"] = str(self.root / "another folder")
                else:
                    values["modules"][0]["owner"] = "another owner"
                with self.assertRaisesRegex(RunnerError, "changed"):
                    create_application(values)
                self.assertFalse(Path(values["directory"]).exists())

    def test_multi_module_ids_are_bounded_distinct_stable_and_dependencies_drafted(self):
        first_id, second_id = "a" * 80, "a" * 79 + "b"
        second_plan = self.root / "second.json"
        config = deepcopy(self.config)
        config["evaluation"]["agent_id"] = "second-engine"
        write(second_plan, config)
        self.values["modules"][0]["id"] = first_id
        self.values["modules"].append({"id": second_id, "profile": "decision", "personas": [],
                                       "depends_on": [first_id],
                                       "plans": [{"path": str(second_plan), "mode": "read_only"}]})
        first = preview_application(self.values)
        second = preview_application(self.values)
        self.assertEqual(first, second)
        ids = [suite["id"] for module in first["manifest"]["modules"] for suite in module["suites"]]
        self.assertEqual(len(set(ids)), 2)
        self.assertTrue(all(re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", key) for key in ids))
        objectives = first["modules"][1]["objectives"]
        self.assertEqual(objectives[-1]["dependency"], first_id)
        self.assertLessEqual(len(objectives[-1]["id"]), 80)
        self.values["modules"][1]["plans"][0]["path"] = str(self.plan)
        duplicate = preview_application(self.values)
        self.assertIn("duplicate_plan", {issue["code"] for issue in duplicate["preflight"]["issues"]})

    def test_next_steps_use_actual_paths_and_platform_shell_quoting(self):
        self.values["directory"] = str(self.root / "release O'Brien $literal `text` & space")
        self.values["host_os"] = "untrusted-client-value"
        result = preview_application(self.values)
        self.assertEqual(result["shell"], "PowerShell" if os.name == "nt" else "POSIX shell")
        command = result["next_steps"][0]["command"]
        if os.name == "nt":
            self.assertIn("O''Brien", command)
            self.assertTrue(command.startswith("& 'esx-eval'"))
        else:
            self.assertIn(result["manifest_path"], shlex.split(command))
        args = ["esx-eval", "release", "preflight", "--manifest", "O'Brien $HOME `cmd` & space/release.json"]
        self.assertEqual(shlex.split(release_setup._command(args, windows=False)), args)
        quoted = release_setup._command(args, windows=True)
        tokens = re.findall(r"'((?:[^']|'')*)'", quoted)
        self.assertEqual([item.replace("''", "'") for item in tokens], args)
        self.assertEqual([step["executes_plans"] for step in result["next_steps"]], [False, True, False])


class ApplicationPageTests(unittest.TestCase):
    def test_html_escapes_token_and_directory_without_breaking_script_or_attributes(self):
        payload = '\"> </script><script>alert("x")</script>&\u2028\u2029__SETUP_VALUE__'
        page = application_setup_html(payload, payload)
        parsed = PageParser()
        parsed.feed(page)
        self.assertEqual(parsed.tags.count("script"), 1)
        self.assertEqual(parsed.attributes["directory"]["value"], payload)
        token = re.search(r"const token=(.*);", parsed.script).group(1)
        self.assertEqual(json.loads(token), payload)
        self.assertNotIn("</script", token.lower())
        self.assertIn("\\u003c", token)
        self.assertIn("&lt;/script&gt;", page)

    def test_page_contract_has_safe_case_controls_three_steps_and_both_setup_links(self):
        page = application_setup_html("csrf-token", None)
        parsed = PageParser()
        parsed.feed(page)
        self.assertEqual(parsed.tags.count("section"), 3)
        self.assertEqual(parsed.tags.count("h2"), 3)
        for required in ('href="/"', 'href="/browser"', 'prefers-color-scheme:dark',
                         '/api/application/preview', '/api/application/create', 'X-ESX-Setup-Token',
                         'textContent', 'cases.selectedOptions', 'option.value=item.case_id',
                         'suite_id:suite.value', 'Remove module', 'Remove plan', 'Remove binding',
                         'Add review note', 'review_scope', 'manifest_json'):
            self.assertIn(required, page)
        for forbidden in ('innerHTML', 'insertAdjacentHTML', 'document.write', '<script src=', '<link ',
                          'JSON ARRAY', 'custom_cases', 'eval('):
            self.assertNotIn(forbidden, page)
        self.assertIn("not AI decision quality", page)
        self.assertIn("Manual review notes stay visible", page)
        self.assertIn("disabled", parsed.attributes["create"])
        self.assertIn("pred-application-release", parsed.attributes["directory"]["value"])


if __name__ == "__main__":
    unittest.main()
