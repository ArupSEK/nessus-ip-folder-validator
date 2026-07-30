import unittest

from ip_utils import normalize_ip


class IpUtilsTests(unittest.TestCase):
    def test_normalize_plain_ip(self):
        self.assertEqual(normalize_ip("192.168.1.10"), "192.168.1.10")

    def test_normalize_cidr(self):
        self.assertEqual(normalize_ip("10.10.10.25/24"), "10.10.10.25")

    def test_normalize_from_mixed_text(self):
        self.assertEqual(normalize_ip("host-01 / 172.16.0.5"), "172.16.0.5")

    def test_invalid_returns_none(self):
        self.assertIsNone(normalize_ip("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
