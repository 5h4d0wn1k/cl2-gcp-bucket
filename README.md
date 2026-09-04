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
# Scan a specific bucket (with API key)
python3 gcs_scanner.py --api-key AIza... --bucket my-target-bucket

# Scan with service account
python3 gcs_scanner.py --sa-json service-account.json --bucket my-bucket

# Enumerate from wordlist
python3 gcs_scanner.py --api-key AIza... --enum

# List objects in a bucket
python3 gcs_scanner.py --api-key AIza... --bucket my-bucket --list-objects

# Full scan with JSON output
python3 gcs_scanner.py --api-key AIza... --bucket my-bucket --output results.json
```

## Example Output

```
  Scanning GCS Bucket: my-target-bucket
============================================================
  Public Read:     YES — PUBLIC
    Role:          roles/storage.objectViewer
  Public Write:    No
  Default ACL:     Public (allUsers)
  CORS:            Wildcard origin (*)
  Lifecycle:       0 rules
  Versioning:      Disabled
  Labels:          {}
  IAM Bindings:    2
    ⚠  roles/storage.objectViewer → allUsers
  Risk Score:      50/100 (HIGH)
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

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
