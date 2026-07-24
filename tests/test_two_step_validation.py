from __future__ import annotations

import io
import unittest

import pandas as pd

from two_step_validation import (
    build_location_index,
    candidate_scan_records,
    deep_validate_selected,
)
from nessus_fixed import ScanRecord


class DiscoveryClient:
    def __init__(self):
        self.detail_calls = []

    def scan_details(self, scan_id, history_id=None, history_uuid=None):
        self.detail_calls.append((scan_id, history_id, history_uuid))
        return {
            "settings": {"text_targets": "10.0.0.10"},
            "hosts": [{"host_id": 1, "hostname": "10.0.0.10"}],
            "info": {
                "scan_start": 100,
                "status": "completed",
                "history_id": 8,
            },
        }


class DeepHostClient:
    def __init__(self):
        self.scan_detail_calls = 0
        self.host_detail_calls = 0

    def scan_details(self, scan_id, history_id=None, history_uuid=None):
        self.scan_detail_calls += 1
        return {
            "hosts": [
                {"host_id": 1, "hostname": "10.0.0.10"},
                {"host_id": 2, "hostname": "10.0.0.11"},
            ],
            "info": {"scan_start": 100, "status": "completed"},
        }

    def host_details(
        self,
        scan_id,
        host_id,
        history_id=None,
        history_uuid=None,
    ):
        self.host_detail_calls += 1
        ip = "10.0.0.10" if str(host_id) == "1" else "10.0.0.11"
        return {
            "info": {"host-ip": ip},
            "vulnerabilities": [
                {
                    "plugin_id": "141118",
                    "plugin_name": "Valid Credentials Provided",
                    "plugin_output": "Authentication succeeded",
                }
            ],
        }


class DeepCSVClient:
    def __init__(self):
        self.export_calls = 0

    def export_scan_csv(self, scan_id, history_id=None):
        self.export_calls += 1
        frame = pd.DataFrame(
            [
                {
                    "Host": "10.0.0.10",
                    "Plugin ID": "141118",
                    "Name": "Valid Credentials Provided",
                    "Plugin Output": "Authentication succeeded",
                    "Risk": "Info",
                },
                {
                    "Host": "10.0.0.11",
                    "Plugin ID": "141118",
                    "Name": "Valid Credentials Provided",
                    "Plugin Output": "Authentication succeeded",
                    "Risk": "Info",
                },
            ]
        )
        return frame.to_csv(index=False).encode("utf-8")


class TwoStepValidationTests(unittest.TestCase):
    def scans(self):
        return [
            ScanRecord(
                scan_id="1",
                schedule_uuid="schedule-1",
                name="Linux 10.0.0.10 10.0.0.11",
                folder_id="3",
                folder_name="Linux",
                status="completed",
                modified="2026-07-20 10:00:00 UTC",
                name_ips=("10.0.0.10", "10.0.0.11"),
            ),
            ScanRecord(
                scan_id="2",
                schedule_uuid="schedule-2",
                name="Unrelated scan",
                folder_id="4",
                folder_name="Windows",
                status="completed",
                modified="2026-07-19 10:00:00 UTC",
            ),
        ]

    def selected_rows(self):
        return pd.DataFrame(
            [
                {
                    "normalized_ip": "10.0.0.10",
                    "folder_name": "Linux",
                    "scan_name": "Linux 10.0.0.10 10.0.0.11",
                    "scan_id": "1",
                    "api_id": "schedule-1",
                    "history_id": "8",
                    "history_uuid": "",
                    "scan_date": "2026-07-20 10:00:00 UTC",
                    "scan_status": "completed",
                    "history_available": True,
                    "presence_type": "Scan result",
                    "result_note": "",
                    "evidence_source": "Low API Discovery",
                    "host_id": "1",
                },
                {
                    "normalized_ip": "10.0.0.11",
                    "folder_name": "Linux",
                    "scan_name": "Linux 10.0.0.10 10.0.0.11",
                    "scan_id": "1",
                    "api_id": "schedule-1",
                    "history_id": "8",
                    "history_uuid": "",
                    "scan_date": "2026-07-20 10:00:00 UTC",
                    "scan_status": "completed",
                    "history_available": True,
                    "presence_type": "Scan result",
                    "result_note": "",
                    "evidence_source": "Low API Discovery",
                    "host_id": "2",
                },
            ]
        )

    def test_discovery_opens_only_metadata_candidate(self):
        client = DiscoveryClient()
        records = self.scans()
        candidates = candidate_scan_records({"10.0.0.10"}, records)
        self.assertEqual([scan.scan_id for scan in candidates], ["1"])

        matches, _, stats = build_location_index(
            client,
            {"10.0.0.10"},
            records,
        )
        self.assertEqual(len(client.detail_calls), 1)
        self.assertEqual(stats["scans_opened"], 1)
        self.assertEqual(matches.iloc[0]["scan_id"], "1")

    def test_host_deep_validation_groups_same_scan(self):
        client = DeepHostClient()
        matches, auth, stats = deep_validate_selected(
            client,
            self.selected_rows(),
            self.scans(),
            method="host_details",
        )
        self.assertEqual(client.scan_detail_calls, 1)
        self.assertEqual(client.host_detail_calls, 2)
        self.assertEqual(stats["scan_groups"], 1)
        self.assertEqual(set(matches["normalized_ip"]), {"10.0.0.10", "10.0.0.11"})
        self.assertEqual(len(auth), 2)

    def test_csv_deep_validation_exports_same_scan_once(self):
        client = DeepCSVClient()
        matches, auth, stats = deep_validate_selected(
            client,
            self.selected_rows(),
            self.scans(),
            method="csv_export",
        )
        self.assertEqual(client.export_calls, 1)
        self.assertEqual(stats["scan_groups"], 1)
        self.assertEqual(set(matches["normalized_ip"]), {"10.0.0.10", "10.0.0.11"})
        self.assertEqual(len(auth), 2)


if __name__ == "__main__":
    unittest.main()
