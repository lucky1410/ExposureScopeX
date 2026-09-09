import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from specialized_scan import safe_extract_archive, safe_image_ref, safe_repository_url


class SpecializedTargetValidationTests(unittest.TestCase):
    def test_repository_requires_allowlisted_https_host(self):
        self.assertEqual(
            safe_repository_url("github.com/example/project"),
            "https://github.com/example/project.git",
        )
        with self.assertRaises(ValueError):
            safe_repository_url("https://example.com/example/project")

    def test_image_reference_is_normalized(self):
        self.assertEqual(safe_image_ref("alpine"), "alpine:latest")
        with self.assertRaises(ValueError):
            safe_image_ref("https://registry.example/image")


class MobileArchiveSafetyTests(unittest.TestCase):
    def test_safe_archive_extracts_regular_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "application.apk"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("AndroidManifest.xml", "manifest")
            destination = root / "content"
            safe_extract_archive(archive, destination, max_bytes=1024)
            self.assertEqual((destination / "AndroidManifest.xml").read_text(), "manifest")

    def test_archive_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "application.ipa"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../outside", "unsafe")
            with self.assertRaises(ValueError):
                safe_extract_archive(archive, root / "content", max_bytes=1024)

    def test_archive_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "application.apk"
            link = zipfile.ZipInfo("link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(link, "destination")
            with self.assertRaises(ValueError):
                safe_extract_archive(archive, root / "content", max_bytes=1024)


if __name__ == "__main__":
    unittest.main()
