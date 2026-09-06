import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gcs_scanner as mod

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "fixtures", "gcs-buckets.json")


class TestBase64Url(unittest.TestCase):

    def test_base64url_no_padding(self):
        sig = mod.base64url(b"\x12\x34\x56\x78\x9a\xbc")
        self.assertNotIn("=", sig)
        self.assertNotIn("+", sig)


class TestGCSOfflineAuditor(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(FIXTURE, encoding="utf-8") as fh:
            cls.fixture = json.load(fh)

    def setUp(self):
        self.auditor = mod.GCSOfflineAuditor()

    def test_fixture_audit_produces_findings(self):
        findings = self.auditor.audit(self.fixture["buckets"])
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertIn("severity", f)
            self.assertIn("remediation", f)
            self.assertIn("rule_id", f)
            self.assertNotEqual(f["severity"], "")

    def test_public_iam_binding_detected(self):
        bucket = {
            "name": "pub",
            "iam_policy": {"bindings": [
                {"role": "roles/storage.objectAdmin", "members": ["allUsers"]}
            ]},
        }
        findings = self.auditor.audit([bucket])
        iam = [f for f in findings if f["category"] == "iam_policy"]
        self.assertEqual(len(iam), 1)
        self.assertEqual(iam[0]["severity"], "CRITICAL")

    def test_public_writer_acl_detected(self):
        bucket = {
            "name": "pub",
            "acl_entries": [{"entity": "allUsers", "role": "WRITER"}],
        }
        findings = self.auditor.audit([bucket])
        acl = [f for f in findings if f["category"] == "acl"]
        self.assertEqual(len(acl), 1)
        self.assertEqual(acl[0]["severity"], "CRITICAL")

    def test_wildcard_cors_detected(self):
        bucket = {"name": "c", "cors": [{"origin": ["*"]}]}
        findings = self.auditor.audit([bucket])
        cors = [f for f in findings if f["category"] == "cors"]
        self.assertEqual(len(cors), 1)
        self.assertEqual(cors[0]["rule_id"], "CL2-COR-001")

    def test_private_bucket_no_public_findings(self):
        bucket = {
            "name": "safe",
            "iam_policy": {"bindings": [
                {"role": "roles/storage.objectViewer",
                 "members": ["serviceAccount:svc@example.iam.gserviceaccount.com"]}
            ]},
            "acl_entries": [],
            "uniform_bucket_level_access": True,
            "cors": [{"origin": ["https://app.example.com"]}],
            "versioning": {"enabled": True},
            "lifecycle": {"rule_count": 2},
            "encryption_disable_default_kms": True,
            "logging": {"enabled": True},
        }
        findings = self.auditor.audit([bucket])
        high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
        self.assertEqual(high, [])

    def test_load_fixture(self):
        buckets = mod.load_bucket_fixtures(FIXTURE)
        self.assertEqual(len(buckets), 3)


class TestLiveScannerOfflineHelpers(unittest.TestCase):

    def test_scanner_constructs_without_credentials(self):
        # Offline code path: the live scanner can be instantiated with no keys;
        # the offline Fixture auditor is the default no-arg path.
        scanner = mod.GCSScanner()
        self.assertIsNotNone(scanner)
        self.assertEqual(scanner.api_key, "")

    def test_public_member_constants(self):
        self.assertIn("allUsers", mod.PUBLIC_MEMBERS)
        self.assertEqual(mod.ROLE_SEVERITY["roles/storage.admin"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()