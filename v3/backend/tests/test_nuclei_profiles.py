import unittest

from app.nuclei_profiles import (
    PINNED_TEMPLATE_RELEASE,
    PROFILES,
    inventory_manifest,
    selection_arguments,
)


class NucleiProfileTests(unittest.TestCase):
    def test_profiles_are_monotonic_and_distinct(self) -> None:
        light = set(PROFILES["light"].template_paths)
        medium = set(PROFILES["medium"].template_paths)
        aggressive = set(PROFILES["aggressive"].template_paths)
        self.assertLess(light, medium)
        self.assertLess(medium, aggressive)

    def test_selection_uses_explicit_categories_and_safety_exclusions(self) -> None:
        arguments = selection_arguments("light", "/templates")
        self.assertIn("/templates/http/exposures", arguments)
        self.assertIn("-exclude-tags", arguments)
        self.assertIn("-exclude-type", arguments)
        self.assertIn("-no-interactsh", arguments)
        self.assertNotIn("/templates/http/cves", arguments)

    def test_inventory_is_deduplicated_and_release_pinned(self) -> None:
        manifest = inventory_manifest("light", ["b.yaml", "a.yaml", "b.yaml", ""])
        self.assertEqual(manifest["template_release"], PINNED_TEMPLATE_RELEASE)
        self.assertEqual(manifest["selected_template_count"], 2)
        self.assertEqual(manifest["selected_templates"], ["a.yaml", "b.yaml"])


if __name__ == "__main__":
    unittest.main()
