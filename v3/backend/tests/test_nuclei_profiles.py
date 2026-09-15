import unittest
from pathlib import Path

from app.nuclei_profiles import (
    LIGHT_TEMPLATE_RELEASE,
    PINNED_TEMPLATE_RELEASE,
    PROFILES,
    inventory_manifest,
    maximum_template_count,
    selection_arguments,
)


class NucleiProfileTests(unittest.TestCase):
    def test_profiles_are_distinct(self) -> None:
        light = set(PROFILES["light"].template_paths)
        medium = set(PROFILES["medium"].template_paths)
        aggressive = set(PROFILES["aggressive"].template_paths)
        self.assertNotEqual(light, medium)
        self.assertLess(medium, aggressive)

    def test_light_selection_uses_the_vendored_allowlist_and_safety_exclusions(self) -> None:
        arguments = selection_arguments("light", "/templates")
        template_root = Path(arguments[1])
        self.assertEqual(template_root.name, "light")
        self.assertEqual(len(list(template_root.glob("*.yaml"))), 3)
        self.assertIn("-exclude-tags", arguments)
        self.assertIn("-exclude-type", arguments)
        self.assertIn("-no-interactsh", arguments)
        self.assertNotIn("/templates/http/cves", arguments)
        self.assertEqual(maximum_template_count("light"), 3)
        self.assertIsNone(maximum_template_count("medium"))

    def test_light_templates_are_get_only_and_disable_redirects(self) -> None:
        template_root = Path(selection_arguments("light", "/templates")[1])
        for template in template_root.glob("*.yaml"):
            content = template.read_text(encoding="utf-8")
            self.assertIn("method: GET", content, template.name)
            self.assertIn("redirects: false", content, template.name)
            self.assertNotIn("raw:", content, template.name)

    def test_inventory_is_deduplicated_and_records_its_light_release(self) -> None:
        manifest = inventory_manifest("light", ["b.yaml", "a.yaml", "b.yaml", ""])
        self.assertEqual(manifest["template_release"], LIGHT_TEMPLATE_RELEASE)
        self.assertEqual(manifest["selected_template_count"], 2)
        self.assertEqual(manifest["selected_templates"], ["a.yaml", "b.yaml"])
        self.assertEqual(len(manifest["template_set_sha256"]), 64)

    def test_broader_profiles_keep_the_pinned_upstream_release(self) -> None:
        self.assertEqual(inventory_manifest("medium", ["a.yaml"])["template_release"], PINNED_TEMPLATE_RELEASE)


if __name__ == "__main__":
    unittest.main()
