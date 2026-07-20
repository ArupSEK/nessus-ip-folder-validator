from __future__ import annotations

import unittest
import pandas as pd

from ip_utils import extract_ips_from_text, normalize_ip
from nessus_fixed import ScanRecord, build_index_fast_api, summarize_results


class TargetOnlyClient:
    def scan_details(self, scan_id, history_id=None, history_uuid=None):
        if history_id:
            return {"hosts": [], "info": {"scan_start": 200}}
        return {
            "settings": {"text_targets": "10.0.0.5"},
            "hosts": [],
            "info": {"scan_start": 200},
        }

    def scan_history(self, scan_id):
        return [
            {
                "id": 7,
                "scan_uuid": "hist-7",
                "status": "completed",
                "start_date": 200,
            }
        ]

    def host_details(self, *args, **kwargs):
        return {}


class HostDetailFallbackClient:
    def scan_details(self, scan_id, history_id=None, history_uuid=None):
        if history_id:
            return {
                "hosts": [
                    {"host_id": 44, "hostname": "server01.example.local"}
                ],
                "info": {"scan_start": 300},
            }
        return {"settings": {}, "hosts": []}

    def scan_history(self, scan_id):
        return [
            {
                "id": 9,
                "scan_uuid": "hist-9",
                "status": "completed",
                "start_date": 300,
            }
        ]

    def host_details(
        self, scan_id, host_id, history_id=None, history_uuid=None
    ):
        return {
            "info": {"host-ip": "10.0.0.6"},
            "vulnerabilities": [
                {
                    "plugin_id": "141118",
                    "plugin_name": "Valid Credentials Provided",
                    "plugin_output": "Authentication succeeded",
                }
            ],
        }


class NoHistoryClient:
    def scan_details(self, scan_id, history_id=None, history_uuid=None):
        return {
            "settings": {"text_targets": "10.0.0.7"},
            "hosts": [],
        }

    def scan_history(self, scan_id):
        return []

    def host_details(self, *args, **kwargs):
        return {}


class DetectionTests(unittest.TestCase):
    def scan(self, name="Linux 10.0.0.5"):
        return ScanRecord(
            scan_id="12",
            schedule_uuid="schedule-12",
            name=name,
            folder_id="3",
            folder_name="Linux",
            status="completed",
            modified="2026-07-20 10:00:00 UTC",
        )

    def test_ip_normalization_accepts_cidr_and_mixed_text(self):
        self.assertEqual(normalize_ip("10.0.0.5/32"), "10.0.0.5")
        self.assertEqual(normalize_ip("server / 10.0.0.6"), "10.0.0.6")
        self.assertEqual(
            extract_ips_from_text("10.0.0.5, 10.0.0.6"),
            {"10.0.0.5", "10.0.0.6"},
        )

    def test_configured_target_is_reported_when_hosts_are_empty(self):
        matches, auth = build_index_fast_api(
            TargetOnlyClient(),
            {"10.0.0.5"},
            [self.scan()],
            include_history=False,
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches.iloc[0]["presence_type"], "Configured target")
        self.assertIn("no host result", matches.iloc[0]["result_note"].lower())
        self.assertTrue(auth.empty)

    def test_fqdn_host_is_resolved_automatically_from_host_details(self):
        matches, auth = build_index_fast_api(
            HostDetailFallbackClient(),
            {"10.0.0.6"},
            [self.scan("Linux server01")],
            include_history=False,
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches.iloc[0]["normalized_ip"], "10.0.0.6")
        self.assertEqual(matches.iloc[0]["presence_type"], "Scan result")
        self.assertFalse(auth.empty)

    def test_no_history_is_reported_as_scan_not_performed(self):
        matches, _ = build_index_fast_api(
            NoHistoryClient(),
            {"10.0.0.7"},
            [self.scan("Linux 10.0.0.7")],
            include_history=False,
        )
        self.assertEqual(len(matches), 1)
        self.assertFalse(bool(matches.iloc[0]["history_available"]))
        self.assertIn(
            "scan not performed", matches.iloc[0]["result_note"].lower()
        )

    def test_summary_uses_only_latest_history_auth_evidence(self):
        input_rows = pd.DataFrame(
            [{"Input IP": "10.0.0.8", "Normalized IP": "10.0.0.8"}]
        )
        matches = pd.DataFrame(
            [
                {
                    "normalized_ip": "10.0.0.8",
                    "folder_name": "Linux",
                    "scan_name": "old",
                    "scan_id": "1",
                    "history_id": "old-h",
                    "history_uuid": "",
                    "scan_date": "2026-07-01 10:00:00 UTC",
                    "scan_status": "completed",
                    "history_available": True,
                    "presence_type": "Scan result",
                    "result_note": "",
                    "evidence_source": "CSV Export",
                    "host_id": "",
                },
                {
                    "normalized_ip": "10.0.0.8",
                    "folder_name": "Linux",
                    "scan_name": "new",
                    "scan_id": "1",
                    "history_id": "new-h",
                    "history_uuid": "",
                    "scan_date": "2026-07-20 10:00:00 UTC",
                    "scan_status": "completed",
                    "history_available": True,
                    "presence_type": "Scan result",
                    "result_note": "",
                    "evidence_source": "CSV Export",
                    "host_id": "",
                },
            ]
        )
        auth = pd.DataFrame(
            [
                {
                    "normalized_ip": "10.0.0.8",
                    "scan_id": "1",
                    "history_id": "old-h",
                    "history_uuid": "",
                    "plugin_id": "104410",
                    "plugin_name": "Authentication failed",
                    "plugin_output": "Old failure",
                    "risk": "Info",
                },
                {
                    "normalized_ip": "10.0.0.8",
                    "scan_id": "1",
                    "history_id": "new-h",
                    "history_uuid": "",
                    "plugin_id": "141118",
                    "plugin_name": "Valid credentials",
                    "plugin_output": "Latest success",
                    "risk": "Info",
                },
            ]
        )
        summary, _ = summarize_results(input_rows, matches, auth)
        self.assertEqual(summary.iloc[0]["Latest Scan Name"], "new")
        self.assertEqual(
            summary.iloc[0]["Authentication Status"], "Authenticated"
        )
        self.assertEqual(
            summary.iloc[0]["Authentication Failure Reason"],
            "Latest success",
        )


if __name__ == "__main__":
    unittest.main()
