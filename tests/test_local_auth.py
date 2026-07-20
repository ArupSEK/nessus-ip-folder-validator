from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from local_auth import LocalAuthError, LocalAuthManager


class LocalAuthManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_path = Path(self.temp_dir.name) / "auth.json"
        self.auth = LocalAuthManager(self.auth_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_first_run_is_not_configured(self) -> None:
        self.assertFalse(self.auth.is_configured())
        self.assertEqual(self.auth.configured_username(), "")

    def test_configure_and_verify(self) -> None:
        self.auth.configure("admin", "StrongPass123!")

        self.assertTrue(self.auth.is_configured())
        self.assertEqual(self.auth.configured_username(), "admin")
        self.assertTrue(self.auth.verify("admin", "StrongPass123!"))
        self.assertFalse(self.auth.verify("admin", "wrong-password"))
        self.assertFalse(self.auth.verify("other", "StrongPass123!"))

        payload = json.loads(self.auth_path.read_text(encoding="utf-8"))
        self.assertNotIn("StrongPass123!", self.auth_path.read_text(encoding="utf-8"))
        self.assertIn("salt", payload)
        self.assertIn("password_hash", payload)
        self.assertGreaterEqual(int(payload["iterations"]), 100_000)

    def test_rejects_short_password(self) -> None:
        with self.assertRaises(LocalAuthError):
            self.auth.configure("admin", "short")
        self.assertFalse(self.auth_path.exists())

    def test_rejects_blank_username(self) -> None:
        with self.assertRaises(LocalAuthError):
            self.auth.configure("   ", "StrongPass123!")
        self.assertFalse(self.auth_path.exists())

    def test_corrupted_config_fails_closed(self) -> None:
        self.auth_path.write_text("not-json", encoding="utf-8")
        self.assertFalse(self.auth.is_configured())
        self.assertFalse(self.auth.verify("admin", "StrongPass123!"))


if __name__ == "__main__":
    unittest.main()
