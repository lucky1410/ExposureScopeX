import unittest

from pydantic import ValidationError

from app.profiles import PLAN_VERSION, compile_plan
from app.schemas import AssessmentCreate, WebAuthentication
from app.target_planning import canonical_http_url, nuclei_targets
from app.methodology_cases import (
    canonical_observation_key,
    coverage_records,
    evaluate_evidence_oracle,
    observation_evidence_kinds,
)


class ContractTests(unittest.TestCase):
    def test_light_plan_is_ordered_and_bounded(self) -> None:
        plan = compile_plan("light", "https://example.test")
        self.assertEqual(plan["version"], PLAN_VERSION)
        self.assertEqual([stage["position"] for stage in plan["stages"]], list(range(8)))
        self.assertEqual(
            [stage["adapter"] for stage in plan["stages"]],
            [
                "scope_preflight", "subdomain_enumeration", "http_profile", "tls_service_discovery",
                "authenticated_crawl", "security_headers", "nuclei_baseline",
                "evidence_validation",
            ],
        )
        self.assertTrue(all(stage["timeout_seconds"] > 0 for stage in plan["stages"]))
        self.assertFalse(plan["stages"][1]["required"])
        self.assertTrue(all(stage["required"] for stage in plan["stages"] if stage["adapter"] != "subdomain_enumeration"))

    def test_medium_and_aggressive_are_complete_bounded_pipelines(self) -> None:
        medium = compile_plan("medium", "https://example.test")
        aggressive = compile_plan("aggressive", "https://example.test")
        expected = [
            "scope_preflight", "http_profile", "tls_service_discovery",
            "authenticated_crawl", "standards_discovery", "application_surface_inventory",
            "authenticated_session_review", "api_contract_review", "security_headers",
            "nuclei_baseline", "evidence_validation",
        ]
        self.assertEqual([stage["adapter"] for stage in medium["stages"]], expected)
        self.assertEqual(
            [stage["adapter"] for stage in aggressive["stages"]],
            [*expected[:9], "route_security_policy_review", *expected[9:]],
        )
        self.assertTrue(all(stage["timeout_seconds"] > 0 for stage in medium["stages"]))
        self.assertGreater(
            sum(stage["timeout_seconds"] for stage in aggressive["stages"]),
            sum(stage["timeout_seconds"] for stage in medium["stages"]),
        )
        self.assertEqual(medium["safety_class"], "non_exploitative")
        self.assertEqual(aggressive["safety_class"], "non_exploitative")

    def test_target_credentials_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            AssessmentCreate(
                name="invalid",
                target="https://user:password@example.test",
                mode="light",
                authorization_confirmed=True,
            )

    def test_non_http_target_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            AssessmentCreate(
                name="invalid",
                target="file:///etc/passwd",
                mode="light",
                authorization_confirmed=True,
            )

    def test_authenticated_assessment_contract(self) -> None:
        authentication = WebAuthentication(
            login_url="http://dvwa.lab.internal/login.php",
            username="authorized-user",
            password="authorized-password",
        )
        assessment = AssessmentCreate(
            name="authenticated",
            target="http://dvwa.lab.internal",
            mode="light",
            authorization_confirmed=True,
            authentication=authentication,
        )
        self.assertEqual(assessment.authentication.login_url, "http://dvwa.lab.internal/login.php")

    def test_nuclei_targets_preserve_safe_authorized_paths(self) -> None:
        targets = nuclei_targets(
            "http://example.test/app",
            [
                "http://example.test/login",
                "http://example.test/vulnerabilities/sqli/?id=1#result",
                "https://example.test/secure",
                "http://outside.test/ignored",
            ],
        )
        self.assertEqual(targets, [
            "http://example.test/app",
            "http://example.test/login",
            "http://example.test/vulnerabilities/sqli/",
        ])

    def test_nuclei_targets_remove_root_and_duplicate_path_slashes(self) -> None:
        self.assertEqual(canonical_http_url("http://example.test//phpinfo.php"), "http://example.test/phpinfo.php")
        self.assertEqual(nuclei_targets("http://example.test/", []), ["http://example.test"])

    def test_authentication_login_must_match_target_hostname(self) -> None:
        with self.assertRaises(ValidationError):
            AssessmentCreate(
                name="invalid-auth-boundary",
                target="https://app.example.test",
                mode="light",
                authorization_confirmed=True,
                authentication=WebAuthentication(
                    login_url="https://outside.example.test/login",
                    username="authorized-user",
                    password="authorized-password",
                ),
            )

    def test_every_planned_stage_has_a_methodology_coverage_case(self) -> None:
        for profile in ("light", "medium", "aggressive"):
            plan = compile_plan(profile, "https://example.test")
            records = coverage_records(plan)
            self.assertEqual(len(records), len(plan["stages"]))
            self.assertEqual({item["adapter"] for item in records}, {item["adapter"] for item in plan["stages"]})
            self.assertTrue(all(item["methodology_version"] == "1.0.0-draft" for item in records))

    def test_header_observation_mapping_and_oracle_use_structured_evidence(self) -> None:
        evidence = {
            "evidence_type": "http_response_header_absence",
            "header_name": "Content-Security-Policy",
        }
        self.assertEqual(canonical_observation_key(evidence), "http.header.absent:content-security-policy")
        status, _ = evaluate_evidence_oracle(evidence, {"headers": {"server": "fixture"}})
        self.assertEqual(status, "passed")
        contradicted, _ = evaluate_evidence_oracle(
            evidence,
            {"headers": {"Content-Security-Policy": "default-src 'self'"}},
        )
        self.assertEqual(contradicted, "failed")

    def test_nuclei_observation_stays_candidate_without_independent_oracle(self) -> None:
        evidence = {"template_id": "phpinfo-files"}
        self.assertEqual(canonical_observation_key(evidence), "nuclei.template:phpinfo-files")
        status, _ = evaluate_evidence_oracle(evidence, None)
        self.assertEqual(status, "not_evaluated")
        self.assertEqual(
            observation_evidence_kinds({
                "template_id": "phpinfo-files",
                "request": "GET /phpinfo.php",
                "response": "HTTP/1.1 200 OK",
                "screenshot_artifact_id": "artifact-id",
            }),
            frozenset({"request", "response", "browser_capture"}),
        )


if __name__ == "__main__":
    unittest.main()
