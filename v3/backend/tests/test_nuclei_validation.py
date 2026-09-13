import unittest

from app.nuclei_validation import evaluate_nuclei_replay, has_safe_replay_oracle


class NucleiIndependentValidationTests(unittest.TestCase):
    def test_phpinfo_requires_reproduced_response_marker(self) -> None:
        self.assertTrue(has_safe_replay_oracle("phpinfo-files"))
        passed, _ = evaluate_nuclei_replay("phpinfo-files", {
            "status": 200,
            "headers": {"content-type": "text/html"},
            "body_preview": "<title>phpinfo()</title><h1>PHP Version 8</h1>",
            "final_url": "https://example.test/phpinfo.php",
        })
        self.assertEqual(passed, "passed")
        failed, _ = evaluate_nuclei_replay("phpinfo-files", {
            "status": 200,
            "headers": {},
            "body_preview": "ordinary page",
            "final_url": "https://example.test/phpinfo.php",
        })
        self.assertEqual(failed, "failed")

    def test_metadata_oracles_are_specific(self) -> None:
        robots, _ = evaluate_nuclei_replay("robots-txt", {
            "status": 200,
            "headers": {"content-type": "text/plain"},
            "body_preview": "User-agent: *\nDisallow: /private",
            "final_url": "https://example.test/robots.txt",
        })
        apache, _ = evaluate_nuclei_replay("apache-detect", {
            "status": 200,
            "headers": {"server": "Apache/2.4"},
            "body_preview": "",
            "final_url": "https://example.test/",
        })
        self.assertEqual(robots, "passed")
        self.assertEqual(apache, "passed")

    def test_unknown_template_is_not_auto_confirmed(self) -> None:
        self.assertFalse(has_safe_replay_oracle("unknown-template"))
        status, _ = evaluate_nuclei_replay("unknown-template", {})
        self.assertEqual(status, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
