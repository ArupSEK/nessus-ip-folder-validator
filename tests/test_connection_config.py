from __future__ import annotations

import unittest

from connection_config import ConnectionConfigError, validate_connection


class ConnectionConfigTests(unittest.TestCase):
    def test_normalizes_valid_connection(self) -> None:
        result = validate_connection(
            " https://192.168.1.10:8834/ ",
            " access-key ",
            " secret-key ",
            False,
            120,
        )
        self.assertEqual(result["base_url"], "https://192.168.1.10:8834")
        self.assertEqual(result["access_key"], "access-key")
        self.assertEqual(result["secret_key"], "secret-key")
        self.assertFalse(result["verify_ssl"])
        self.assertEqual(result["timeout"], 120)

    def test_rejects_incomplete_url(self) -> None:
        with self.assertRaises(ConnectionConfigError):
            validate_connection("192.168.1.10:8834", "a", "b")

    def test_requires_both_keys(self) -> None:
        with self.assertRaises(ConnectionConfigError):
            validate_connection("https://cloud.tenable.com", "", "b")
        with self.assertRaises(ConnectionConfigError):
            validate_connection("https://cloud.tenable.com", "a", "")


if __name__ == "__main__":
    unittest.main()
