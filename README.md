# CL2 — GCP Bucket Scanner

GCP Cloud Storage bucket enumeration, permission analysis, and public access detection.

## Overview

This project implements a GCS bucket security scanner that:
- Enumerates GCS buckets via API or wordlist brute-force
- Checks IAM policies for public (allUsers) bindings
- Analyzes default object ACLs
- Detects wildcard CORS configurations
- Checks versioning, lifecycle, and labels
- Calculates a risk score for each bucket

## Features

- **Bucket enumeration**: Discover buckets via API listing or wordlist
- **Public access detection**: Find allUsers in IAM bindings and ACLs
- **CORS analysis**: Detect wildcard origin configurations
- **IAM policy review**: Parse and flag dangerous bindings
- **Lifecycle check**: Verify lifecycle rules are configured
- **Risk scoring**: 0–100 score based on misconfigurations
- **JSON export**: Save results for integration with other tools

## Dependencies

**None** — uses only Python standard library (`urllib`, `json`, `hmac`, `hashlib`).

## Usage

```bash
# Offline demo (no cloud, no credentials) — audit bundled fixtures
python3 gcs_scanner.py --demo

# Audit a custom bucket-state fixtures file (offline)
python3 gcs_scanner.py --fixtures fixtures/gcs-buckets.json

# Offline audit with JSON report + CI exit code
python3 gcs_scanner.py --demo --output reports/cl2-report.json --exit-code-on-findings

# Live (authorized, your own project): scan a specific bucket
python3 gcs_scanner.py --api-key AIza... --bucket my-target-bucket

# Scan with service account (credentials supplied at runtime only)
python3 gcs_scanner.py --sa-json service-account.json --bucket my-bucket

# Enumerate from wordlist
python3 gcs_scanner.py --api-key AIza... --enum
```

## Exit Codes

- `0` — completed cleanly (or demo finished without explicit CRITICAL/HIGH gate)
- `1` — error (missing fixtures, unreadable file, bad JSON)
- `2` — CRITICAL/HIGH findings present with `--exit-code-on-findings`

## Live Lab Test Plan

Runs entirely offline against `fixtures/gcs-buckets.json` — no GCP project, no key, no network.

1. **Demo**: `python3 gcs_scanner.py --demo` — expect CRITICAL/HIGH/MEDIUM/LOW findings for the public IAM bindings, public ACL entries, disabled uniform-bucket-level-access, wildcard CORS, disabled versioning, missing lifecycle rules, disabled logging, and Google-managed (non-CMEK) encryption. Exit `0`.
2. **JSON report**: `python3 gcs_scanner.py --demo --output reports/cl2-report.json` — verify the report has `finding_count > 0`, a `summary` map, and per-finding `severity`, `rule_id`, `message`, `remediation`.
3. **CI exit code**: `python3 gcs_scanner.py --demo --exit-code-on-findings; echo $?` — expect `2`.
4. **Unit tests**: `python3 -m unittest discover -s tests -v` — all pass (exercises the full fixture rule set + base64url helper).
5. **Live (optional)**: pass your own `--api-key`/`--sa-json`/`--bucket` at runtime. Credentials are used only for that run and are never written to disk. Only probe buckets in projects you own or are authorized to test.

## Metrics

- Detection rules exercised offline (all real code paths): public IAM binding (CL2-IAM-001), public ACL entry (CL2-ACL-001), wildcard CORS (CL2-COR-001), versioning disabled (CL2-CFG-001), lifecycle missing (CL2-CFG-002), logging disabled (CL2-CFG-003), uniform bucket-level access disabled (CL2-CFG-005), non-CMEK encryption default (CL2-CFG-004)
- Every finding carries `severity`, `category`, `rule_id`, `bucket`, `message`, and a `remediation` string
- Role-severity mapping matches GCS IAM semantics (`roles/storage.admin`/`objectAdmin` → CRITICAL, legacy writer/bucket owner → HIGH)
- Exit-code contract: `0` clean / `1` error / `2` findings (with `--exit-code-on-findings`)
- Zero third-party dependencies; `--demo` requires no network of any kind

## Legal Disclaimer

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the bucket/project owner before using this tool
- Unauthorized enumeration of GCP buckets violates Google Cloud ToS
- This tool should ONLY be used on buckets you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Google Cloud Terms of Service**: Probes against buckets you do not own violate GCP ToS
- **State Laws**: Many states have additional computer crime statutes
- **GDPR/CCPA**: Data access may be subject to privacy regulations

### Acceptable Use
- Testing security of your own GCS buckets
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Enumerating or accessing buckets you do not own
- Downloading data from unauthorized buckets
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
