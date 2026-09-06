#!/usr/bin/env python3
"""CL2 — GCP Cloud Storage Bucket Scanner.

Enumerates GCS buckets, checks permissions, detects public access,
and analyzes bucket policies. Uses only standard library.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


class GCSScanner:
    """GCP Cloud Storage bucket scanner using standard library."""

    API_BASE = "https://storage.googleapis.com"

    # Well-known GCP service account hash suffixes for identification
    KNOWN_SA_SUFFIXES = {
        "cloudservices": "Google Cloud Services",
        "compute": "Google Compute Engine",
        "appspot": "Google App Engine",
        "iam": "Google IAM",
        "cloudbuild": "Google Cloud Build",
        "gcf-admin": "Google Cloud Functions",
    }

    def __init__(self, api_key: str = "", service_account_json: str = ""):
        self.api_key = api_key
        self.service_account_json = service_account_json
        self._access_token = None
        self._token_expiry = 0

    # ── Auth helpers ─────────────────────────────────────────────────

    def _load_sa_credentials(self):
        """Load service account JSON for token generation."""
        if self.service_account_json:
            with open(self.service_account_json) as f:
                return json.load(f)
        return None

    def _get_access_token(self) -> str:
        """Get OAuth2 access token using service account JWT assertion."""
        if self._access_token and time.time() < self._token_expiry:
            return self._access_token

        sa = self._load_sa_credentials()
        if not sa:
            return ""

        now = int(time.time())
        header = base64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload = base64url(json.dumps({
            "iss": sa["client_email"],
            "scope": "https://www.googleapis.com/auth/devstorage.read_only",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        }).encode())

        # For production, would need RSA signing with service account private key
        # Using API key fallback for standard-library-only implementation
        self._access_token = ""
        return self._access_token

    # ── HTTP helpers ─────────────────────────────────────────────────

    def _request(self, url: str) -> tuple[int, dict | str]:
        """Make GET request to GCS API."""
        if self.api_key:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}key={self.api_key}"

        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                return resp.status, data
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                data = {"error": body}
            return exc.code, data
        except Exception as exc:
            return 0, {"error": str(exc)}

    def _request_no_key(self, url: str) -> tuple[int, dict | str]:
        """Make GET request without API key (for anonymous probe)."""
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                return resp.status, data
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                data = {"error": body}
            return exc.code, data
        except Exception as exc:
            return 0, {"error": str(exc)}

    # ── Bucket enumeration ───────────────────────────────────────────

    def list_all_buckets(self) -> list[dict]:
        """List all GCS buckets in the project (requires API key or token)."""
        url = f"{self.API_BASE}/storage/v1/b"
        status, data = self._request(url)
        if status != 200:
            print(f"[!] Failed to list buckets (HTTP {status})")
            if isinstance(data, dict) and "error" in data:
                print(f"    {data['error']}")
            return []
        return data.get("items", [])

    def enum_from_wordlist(self, wordlist: list[str]) -> list[dict]:
        """Check which bucket names from a wordlist exist."""
        found = []
        for name in wordlist:
            url = f"{self.API_BASE}/storage/v1/b/{name}"
            status, data = self._request(url)
            if status == 200:
                print(f"  [+] EXISTS: {name}")
                found.append(data)
            elif status == 403:
                print(f"  [=] EXISTS (private): {name}")
                found.append({"id": name, "access": "denied"})
        return found

    # ── Permission checks ────────────────────────────────────────────

    def check_all_users_read(self, bucket: str) -> dict:
        """Check if bucket is publicly readable (allUsers)."""
        url = f"{self.API_BASE}/storage/v1/b/{bucket}/iam"
        status, data = self._request(url)
        result = {"bucket": bucket, "public_read": False, "bindings": []}
        if status == 200:
            bindings = data.get("bindings", [])
            result["bindings"] = bindings
            for binding in bindings:
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    role = binding.get("role", "")
                    if "viewer" in role or "reader" in role or "storage.objectViewer" in role:
                        result["public_read"] = True
                        result["public_role"] = role
                        result["public_members"] = members
        return result

    def check_all_users_write(self, bucket: str) -> dict:
        """Check if bucket is publicly writable."""
        url = f"{self.API_BASE}/storage/v1/b/{bucket}/iam"
        status, data = self._request(url)
        result = {"bucket": bucket, "public_write": False}
        if status == 200:
            for binding in data.get("bindings", []):
                members = binding.get("members", [])
                role = binding.get("role", "")
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    if any(r in role for r in ["admin", "editor", "writer", "ObjectCreator", "ObjectAdmin"]):
                        result["public_write"] = True
                        result["write_role"] = role
        return result

    def check_default_object_acl(self, bucket: str) -> dict:
        """Check default object ACL."""
        url = f"{self.API_BASE}/storage/v1/b/{bucket}/defaultObjectAcl"
        status, data = self._request(url)
        result = {"bucket": bucket, "status": status, "acl": []}
        if status == 200:
            result["acl"] = data.get("items", [])
            for entry in result["acl"]:
                entity = entry.get("entity", "")
                if "allUsers" in entity:
                    result["public_default_acl"] = True
                    result["public_entity"] = entity
        return result

    def check_cors(self, bucket: str) -> dict:
        """Check CORS configuration."""
        url = f"{self.API_BASE}/storage/v1/b/{bucket}/cors"
        status, data = self._request(url)
        result = {"bucket": bucket, "status": status, "cors": data if status == 200 else []}
        if status == 200 and isinstance(data, list):
            for rule in data:
                origins = rule.get("origin", [])
                if "*" in origins:
                    result["wildcard_cors"] = True
        return result

    def check_lifecycle(self, bucket: str) -> dict:
        """Check lifecycle rules."""
        url = f"{self.API_BASE}/storage/v1/b/{bucket}/lifecycle"
        status, data = self._request(url)
        result = {"bucket": bucket, "status": status}
        if status == 200:
            rules = data.get("rule", [])
            result["rules"] = rules
            result["rule_count"] = len(rules)
        return result

    def check_versioning(self, bucket: str) -> dict:
        """Check bucket versioning."""
        url = f"{self.API_BASE}/storage/v1/b/{bucket}"
        status, data = self._request(url)
        result = {"bucket": bucket, "status": status}
        if status == 200:
            ver = data.get("versioning", {})
            result["versioning_enabled"] = ver.get("enabled", False)
        return result

    def check_labels(self, bucket: str) -> dict:
        """Check bucket labels."""
        url = f"{self.API_BASE}/storage/v1/b/{bucket}"
        status, data = self._request(url)
        result = {"bucket": bucket, "labels": {}}
        if status == 200:
            result["labels"] = data.get("labels", {})
        return result

    def check_iam_policy(self, bucket: str) -> dict:
        """Retrieve IAM policy."""
        url = f"{self.API_BASE}/storage/v1/b/{bucket}/iam"
        status, data = self._request(url)
        result = {"bucket": bucket, "status": status}
        if status == 200:
            result["policy"] = data
            result["binding_count"] = len(data.get("bindings", []))
            dangerous = []
            for binding in data.get("bindings", []):
                role = binding.get("role", "")
                members = binding.get("members", [])
                if "allUsers" in members:
                    dangerous.append({"role": role, "members": members})
            result["public_bindings"] = dangerous
        return result

    # ── Content listing ──────────────────────────────────────────────

    def list_objects(self, bucket: str, prefix: str = "", max_results: int = 100) -> list[dict]:
        """List objects in a bucket."""
        params = urllib.parse.urlencode({"maxResults": max_results, "prefix": prefix})
        url = f"{self.API_BASE}/storage/v1/b/{bucket}/o?{params}"
        status, data = self._request(url)
        if status == 200:
            return data.get("items", [])
        print(f"[!] Cannot list objects in {bucket} (HTTP {status})")
        return []

    # ── Full scan ────────────────────────────────────────────────────

    def scan_bucket(self, bucket: str) -> dict:
        """Perform full permission scan on a bucket."""
        print(f"\n{'='*60}")
        print(f"  Scanning GCS Bucket: {bucket}")
        print(f"{'='*60}")

        results = {"bucket": bucket}

        pub_read = self.check_all_users_read(bucket)
        results["public_read"] = pub_read["public_read"]
        print(f"  Public Read:     {'YES — PUBLIC' if pub_read['public_read'] else 'No'}")
        if pub_read.get("public_role"):
            print(f"    Role:          {pub_read['public_role']}")

        pub_write = self.check_all_users_write(bucket)
        results["public_write"] = pub_write["public_write"]
        print(f"  Public Write:    {'YES — CRITICAL' if pub_write['public_write'] else 'No'}")

        default_acl = self.check_default_object_acl(bucket)
        results["default_acl"] = default_acl
        if default_acl.get("public_default_acl"):
            print(f"  Default ACL:     Public ({default_acl.get('public_entity', '')})")
        else:
            print(f"  Default ACL:     Private")

        cors = self.check_cors(bucket)
        results["cors"] = cors
        if cors.get("wildcard_cors"):
            print(f"  CORS:            Wildcard origin (*)")
        else:
            print(f"  CORS:            Restrictive")

        lifecycle = self.check_lifecycle(bucket)
        results["lifecycle"] = lifecycle.get("rule_count", 0)
        print(f"  Lifecycle:       {lifecycle.get('rule_count', 0)} rules")

        ver = self.check_versioning(bucket)
        results["versioning"] = ver.get("versioning_enabled", False)
        print(f"  Versioning:      {'Enabled' if ver.get('versioning_enabled') else 'Disabled'}")

        labels = self.check_labels(bucket)
        results["labels"] = labels.get("labels", {})
        if labels.get("labels"):
            print(f"  Labels:          {json.dumps(labels['labels'])}")

        iam = self.check_iam_policy(bucket)
        results["iam"] = iam
        print(f"  IAM Bindings:    {iam.get('binding_count', 0)}")
        if iam.get("public_bindings"):
            for pb in iam["public_bindings"]:
                print(f"    ⚠  {pb['role']} → {', '.join(pb['members'])}")

        public_score = sum([
            40 if pub_read["public_read"] else 0,
            50 if pub_write["public_write"] else 0,
            5 if default_acl.get("public_default_acl") else 0,
            5 if cors.get("wildcard_cors") else 0,
        ])
        results["risk_score"] = min(public_score, 100)
        risk_label = "CRITICAL" if public_score >= 80 else "HIGH" if public_score >= 50 else "MEDIUM" if public_score >= 20 else "LOW"
        print(f"  Risk Score:      {public_score}/100 ({risk_label})")

        return results


class GCSWordlist:
    """Common GCS bucket name patterns."""

    COMMON_NAMES = [
        "backup", "backups", "config", "data", "database", "db",
        "dev", "development", "prod", "production", "staging",
        "logs", "log", "archive", "temp", "test", "tests",
        "assets", "static", "media", "images", "uploads",
        "documents", "docs", "reports", "exports",
        "secrets", "credentials", "keys", "tokens",
        "deploy", "ci", "cd", "build", "pipeline",
        "public", "private", "shared", "internal",
        "www", "web", "website", "cdn", "cache",
        "functions", "serverless", "api",
        "analytics", "warehouse", "bigquery",
        "terraform", "state", "tf-state",
    ]

    @classmethod
    def get_default(cls) -> list[str]:
        return list(cls.COMMON_NAMES)


def base64url(data: bytes) -> str:
    """Base64url encode bytes."""
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def print_banner():
    banner = r"""
    ╔═══════════════════════════════════════════╗
    ║     CL2 — GCP Bucket Scanner              ║
    ║     Standard Library · No Dependencies     ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)


# ---------------------------------------------------------------------------
# Offline fixture auditor
# ---------------------------------------------------------------------------

PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")

ROLE_SEVERITY = {
    "roles/storage.objectViewer": "MEDIUM",
    "roles/storage.objectCreator": "MEDIUM",
    "roles/storage.objectAdmin": "CRITICAL",
    "roles/storage.legacyObjectReader": "MEDIUM",
    "roles/storage.legacyObjectWriter": "HIGH",
    "roles/storage.legacyBucketOwner": "HIGH",
    "roles/storage.admin": "CRITICAL",
    "roles/owner": "CRITICAL",
}


class GCSOfflineAuditor:
    """Detect GCS bucket misconfigurations from realistic fixture state."""

    def audit(self, buckets):
        findings = []
        for bucket in buckets:
            name = bucket.get("name", "unknown-bucket")
            findings.extend(self._audit_iam(name, bucket.get("iam_policy")))
            findings.extend(self._audit_acl(name, bucket.get("acl_entries")))
            findings.extend(self._audit_cors(name, bucket.get("cors")))
            findings.extend(self._audit_config(name, bucket))
        return findings

    def _audit_iam(self, name, iam_policy):
        findings = []
        for binding in (iam_policy or {}).get("bindings", []):
            role = binding.get("role", "")
            for member in binding.get("members", []):
                if member in PUBLIC_MEMBERS:
                    severity = ROLE_SEVERITY.get(role, "HIGH")
                    findings.append({
                        "severity": severity,
                        "category": "iam_policy",
                        "rule_id": "CL2-IAM-001",
                        "bucket": name,
                        "resource": f"gs://{name}",
                        "message": f"IAM binding grants '{role}' to public member '{member}'.",
                        "remediation": "Remove public members from the IAM binding; grant access via "
                                       "service accounts, groups or VPC Service Controls instead.",
                    })
        return findings

    def _audit_acl(self, name, acl_entries):
        findings = []
        for entry in acl_entries or []:
            entity = entry.get("entity", "")
            role = entry.get("role", "")
            if entity not in PUBLIC_MEMBERS:
                continue
            severity = "CRITICAL" if role in ("OWNER", "WRITER") else "MEDIUM"
            findings.append({
                "severity": severity,
                "category": "acl",
                "rule_id": "CL2-ACL-001",
                "bucket": name,
                "resource": f"gs://{name}",
                "message": f"Bucket ACL grants '{role}' to public entity '{entity}'.",
                "remediation": "Turn on uniform bucket-level access and drop public ACL entries; keep "
                               "object access controlled by IAM.",
            })
        return findings

    def _audit_cors(self, name, cors):
        findings = []
        for rule in cors or []:
            origins = rule.get("origin", [])
            if "*" in origins:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "cors",
                    "rule_id": "CL2-COR-001",
                    "bucket": name,
                    "resource": f"gs://{name}",
                    "message": "CORS rule allows wildcard origin '*'; browser-based clients from any "
                               "website can make cross-origin requests.",
                    "remediation": "Restrict CORS origins to explicit trusted domains and methods.",
                })
        return findings

    def _audit_config(self, name, bucket):
        findings = []
        if not bucket.get("versioning", {}).get("enabled", False):
            findings.append({
                "severity": "MEDIUM",
                "category": "versioning",
                "rule_id": "CL2-CFG-001",
                "bucket": name,
                "resource": f"gs://{name}",
                "message": "Object versioning is disabled.",
                "remediation": "Enable versioning to retain object history for recovery and forensics.",
            })

        lifecycle = bucket.get("lifecycle", {})
        rule_count = lifecycle.get("rule_count", len(lifecycle.get("rules", [])))
        if rule_count == 0:
            findings.append({
                "severity": "LOW",
                "category": "lifecycle",
                "rule_id": "CL2-CFG-002",
                "bucket": name,
                "resource": f"gs://{name}",
                "message": "No lifecycle rules configured; storage has no retention or deletion policy.",
                "remediation": "Add lifecycle rules with retention/age conditions to avoid unbounded "
                               "data retention.",
            })

        if bucket.get("logging") and not bucket.get("logging", {}).get("enabled", False):
            findings.append({
                "severity": "MEDIUM",
                "category": "logging",
                "rule_id": "CL2-CFG-003",
                "bucket": name,
                "resource": f"gs://{name}",
                "message": "Cloud Storage access logging is disabled.",
                "remediation": "Enable storage logging to an audit bucket inside the same project.",
            })

        if bucket.get("require_payer"):
            pass  # Requester-pays is a hardening choice, not a finding.

        if bucket.get("uniform_bucket_level_access") is False:
            findings.append({
                "severity": "MEDIUM",
                "category": "uniform_bucket_level_access",
                "rule_id": "CL2-CFG-005",
                "bucket": name,
                "resource": f"gs://{name}",
                "message": "Uniform bucket-level access is disabled; per-object ACLs can override policy.",
                "remediation": "Enable uniform bucket-level access so object ACLs cannot override policy.",
            })

        if not (bucket.get("encryption_disable_default_kms", False)):
            findings.append({
                "severity": "LOW",
                "category": "cmeK",
                "rule_id": "CL2-CFG-004",
                "bucket": name,
                "resource": f"gs://{name}",
                "message": "Bucket uses Google-managed default encryption (no customer-managed key).",
                "remediation": "For compliance-bound workloads, configure a Cloud KMS customer-managed "
                               "key and set default_kms_key_name.",
            })
        return findings


def load_bucket_fixtures(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise FileNotFoundError(f"Fixtures file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in fixtures file {path}: {exc}") from exc
    if isinstance(data, dict):
        return data.get("buckets", [])
    if isinstance(data, list):
        return data
    raise ValueError(f"Unsupported fixture structure in {path}")


def print_offline_report(buckets, findings):
    print("\n" + "=" * 64)
    print("  CL2 — GCP Bucket Offline Misconfiguration Audit")
    print("=" * 64)
    print(f"  Buckets audited: {len(buckets)}")
    print(f"  Findings:        {len(findings)}")
    print("=" * 64)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in counts:
            print(f"    {sev:9s}: {counts[sev]}")
    print()
    for f in findings:
        print(f"  [{f['severity']:8s}] {f['rule_id']} {f['bucket']}")
        print(f"      {f['message']}")
        print(f"      Fix: {f['remediation']}")
    print("\n" + "=" * 64 + "\n")


def write_report(report, output_path):
    parent = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(parent, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
    print(f"[+] JSON report written to {output_path}")


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="GCP Cloud Storage Bucket Scanner")
    parser.add_argument("--api-key", default="", help="Google Cloud API key (your own at runtime only)")
    parser.add_argument("--sa-json", default="", help="Path to service account JSON")
    parser.add_argument("--bucket", default="", help="Specific bucket to scan")
    parser.add_argument("--enum", action="store_true", help="Enumerate from wordlist")
    parser.add_argument("--list-objects", action="store_true", help="List bucket contents")
    parser.add_argument("--prefix", default="", help="Prefix filter for listing")
    parser.add_argument("--wordlist", nargs="*", help="Extra bucket names to check")
    parser.add_argument("--demo", action="store_true",
                        help="Run offline demo against bundled fixture (no network)")
    parser.add_argument("--fixtures", default="",
                        help="Path to bucket-state fixtures JSON (offline audit)")
    parser.add_argument("--output", "-o", default="", help="JSON output file")
    parser.add_argument("--exit-code-on-findings", action="store_true",
                        help="Exit 2 when CRITICAL/HIGH findings exist (CI-friendly)")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    if args.demo or args.fixtures or not (args.bucket or args.enum or args.api_key or args.sa_json):
        fixture = args.fixtures or os.path.join(base_dir, "fixtures", "gcs-buckets.json")
        if not os.path.isfile(fixture):
            print(f"[!] Fixture not found: {fixture}. Run --demo from the repo root.", file=sys.stderr)
            return 1
        print(f"[*] Offline mode — auditing fixtures: {fixture}")
        try:
            buckets = load_bucket_fixtures(fixture)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        findings = GCSOfflineAuditor().audit(buckets)
        print_offline_report(buckets, findings)
        report = {
            "tool": "CL2-GCPBucketOfflineAuditor",
            "mode": "offline-fixture",
            "finding_count": len(findings),
            "summary": {},
            "findings": findings,
        }
        for f in findings:
            report["summary"][f["severity"]] = report["summary"].get(f["severity"], 0) + 1
        output = args.output or os.path.join(base_dir, "reports", "cl2-report.json")
        write_report(report, output)
        if args.exit_code_on_findings and any(f["severity"] in ("CRITICAL", "HIGH") for f in findings):
            return 2
        return 0

    if not args.api_key and not args.sa_json:
        print("[!] Provide --api-key or --sa-json for full functionality")
        print("[!] Proceeding with limited unauthenticated probes...\n")

    scanner = GCSScanner(args.api_key, args.sa_json)
    all_results = []

    if args.bucket:
        result = scanner.scan_bucket(args.bucket)
        all_results.append(result)

        if args.list_objects:
            objects = scanner.list_objects(args.bucket, args.prefix)
            print(f"\n  Objects in {args.bucket}:")
            for obj in objects[:50]:
                name = obj.get("name", "")
                size = obj.get("size", 0)
                print(f"    {name}  ({size} bytes)")
            if len(objects) > 50:
                print(f"    ... and {len(objects) - 50} more")

    if args.enum:
        print("\n[*] Enumerating GCS buckets...")
        names = args.wordlist or GCSWordlist.get_default()
        found = scanner.enum_from_wordlist(names)
        print(f"\n[*] Found {len(found)} accessible buckets")
        for bucket_info in found:
            bid = bucket_info.get("id", "")
            if bid:
                result = scanner.scan_bucket(bid)
                all_results.append(result)

    if args.api_key or args.sa_json:
        print("\n[*] Listing project buckets...")
        buckets = scanner.list_all_buckets()
        print(f"[*] Found {len(buckets)} buckets")
        for bucket_info in buckets:
            bid = bucket_info.get("id", "")
            if bid:
                result = scanner.scan_bucket(bid)
                all_results.append(result)

    if not args.bucket and not args.enum and not (args.api_key or args.sa_json):
        parser.print_help()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n[+] Results saved to {args.output}")

    print("\n[*] Scan complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
