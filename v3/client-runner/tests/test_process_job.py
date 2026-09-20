"""Windows job cleanup must finish before disposable working directories close."""

import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

from esx_eval_runner.process_job import run_windows_job


@unittest.skipUnless(os.name == "nt", "Windows Job Object lifetime contract")
class ProcessJobTests(unittest.TestCase):
    def test_timeout_releases_working_directory_without_cleanup_retry(self):
        for _ in range(5):
            with TemporaryDirectory() as directory:
                self.assertIsNone(run_windows_job([sys.executable, "-c", "import time; time.sleep(30)"], directory, .15))
            self.assertFalse(Path(directory).exists())

    def test_success_reaps_background_child_before_directory_cleanup(self):
        script = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])"
        for _ in range(5):
            with TemporaryDirectory() as directory:
                self.assertEqual(run_windows_job([sys.executable, "-c", script], directory, 5), 0)
            self.assertFalse(Path(directory).exists())

