import unittest

from nessus_client import ScanRecord, build_index_csv_export, build_index_fast_api


class FastApiClientStub:
    def __init__(self):
        self.calls = []

    def scan_history(self, scan_id):
        self.calls.append(("scan_history", scan_id))
        return [{"id": "456", "uuid": "history-uuid", "start_date": 1700000000, "status": "completed"}]

    def scan_details(self, scan_id, history_id=None, history_uuid=None):
        self.calls.append(("scan_details", scan_id, history_id, history_uuid))
        return {"hosts": [{"host_id": "7", "hostname": "10.0.0.1"}]}

    def host_details(self, scan_uuid_or_id, host_id, history_id=None):
        self.calls.append(("host_details", scan_uuid_or_id, host_id, history_id))
        return {
            "vulnerabilities": [
                {
                    "plugin_id": "110095",
                    "plugin_name": "Integration Credential Status by Authentication Protocol - No Issues Found",
                }
            ]
        }


class CsvExportClientStub:
    def __init__(self):
        self.calls = []

    def scan_history(self, scan_id):
        self.calls.append(("scan_history", scan_id))
        return [{"id": "456", "start_date": 1700000000, "status": "completed"}]

    def export_scan_csv(self, scan_id, history_id=None):
        self.calls.append(("export_scan_csv", scan_id, history_id))
        return (
            b"Host,Plugin ID,Name,Plugin Output,Risk\r\n"
            b"10.0.0.1,110095,Integration Credential Status by Authentication Protocol - No Issues Found,,Info\r\n"
        )


class NessusClientIdentifierTests(unittest.TestCase):
    def setUp(self):
        self.scan = ScanRecord(
            scan_id="123",
            scan_uuid="scan-uuid",
            name="Test Scan",
            folder_id="1",
            folder_name="Folder A",
            status="completed",
        )

    def test_fast_api_uses_scan_id_for_history_and_details(self):
        client = FastApiClientStub()

        matches, auth_rows = build_index_fast_api(
            client,
            {"10.0.0.1"},
            [self.scan],
            include_history=True,
            fetch_host_details=True,
        )

        self.assertEqual(client.calls[0], ("scan_history", "123"))
        self.assertEqual(client.calls[1], ("scan_details", "123", "456", "history-uuid"))
        self.assertEqual(client.calls[2], ("host_details", "scan-uuid", "7", "456"))
        self.assertEqual(matches.iloc[0]["normalized_ip"], "10.0.0.1")
        self.assertEqual(auth_rows.iloc[0]["plugin_id"], "110095")

    def test_csv_export_uses_scan_id(self):
        client = CsvExportClientStub()

        matches, auth_rows = build_index_csv_export(
            client,
            {"10.0.0.1"},
            [self.scan],
            include_history=True,
        )

        self.assertEqual(client.calls[0], ("scan_history", "123"))
        self.assertEqual(client.calls[1], ("export_scan_csv", "123", "456"))
        self.assertEqual(matches.iloc[0]["normalized_ip"], "10.0.0.1")
        self.assertEqual(auth_rows.iloc[0]["plugin_id"], "110095")


if __name__ == "__main__":
    unittest.main()
