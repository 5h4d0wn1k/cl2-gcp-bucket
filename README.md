> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# CL2 — GCP Bucket Scanner

CL2 is a **cloud security** auditing tool that finds **GCP Cloud Storage**
buckets and checks them for **public access**, weak **IAM/ACL permissions**, and
misconfigured settings — for **authorized security testing** and education.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/cl2-gcp-bucket)](https://github.com/5h4d0wn1k/cl2-gcp-bucket)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/cl2-gcp-bucket)](https://github.com/5h4d0wn1k/cl2-gcp-bucket)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/cl2-gcp-bucket)](https://github.com/5h4d0wn1k/cl2-gcp-bucket)

## Why CL2

Misconfigured cloud storage is one of the most common data-leak vectors:
publicly readable buckets have exposed billions of records. CL2 automates the
worst-check: discover buckets, audit IAM bindings for `allUsers`/`allAuthenticatedUsers`,
read ACLs and CORS, and verify versioning, lifecycle, logging, and encryption —
then score the risk. It is built purely for **educational and authorized cloud
security testing** on projects you own or have written permission to assess.
Unauthorized enumeration violates Google Cloud ToS and may be illegal.

## Features

- **Bucket enumeration** — via the Google Cloud Storage API or wordlist-driven guessing (`--enum`)
- **Public access detection** — flags `allUsers` IAM bindings and public ACL entries
- **CORS analysis** — catches wildcard origins that enable cross-origin data theft
- **Misconfiguration checks** — versioning, lifecycle, logging, uniform bucket-level access, CMEK encryption
- **Risk scoring** — 0–100 severity rating per bucket with structured findings
- **Offline auditor** — deterministic fixture audits, no cloud account required
- **JSON reports & CI exit codes** — `--output` and `--exit-code-on-findings`
- **Zero dependencies** — Python standard library only (`urllib`, `hmac`, `hashlib`, `json`)

## Quickstart

```bash
# Offline demo — audits bundled fixtures, nothing touches the network
python3 gcs_scanner.py --demo

# Offline audit with JSON report + CI gate
python3 gcs_scanner.py --demo --output reports/cl2-report.json --exit-code-on-findings

# Live scan (your own project, credentials supplied at runtime only)
python3 gcs_scanner.py --api-key <KEY> --bucket my-target-bucket
python3 gcs_scanner.py --sa-json service-account.json --bucket my-bucket

# Wordlist enumeration
python3 gcs_scanner.py --api-key <KEY> --enum

# Tests
python3 -m unittest discover -s tests
```

Custom bucket-state fixtures:
```bash
python3 gcs_scanner.py --fixtures fixtures/gcs-buckets.json
```

## Examples

- `fixtures/gcs-buckets.json` — synthetic bucket states exercising every detection rule (public IAM, public ACL, wildcard CORS, missing versioning/lifecycle/logging, non-CMEK encryption)

## Project structure

- `gcs_scanner.py` — scanner, wordlist, and offline auditor
- `fixtures/` — offline demo data
- `tests/` — unit tests over the full rule set

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md) · [SECURITY.md](SECURITY.md)