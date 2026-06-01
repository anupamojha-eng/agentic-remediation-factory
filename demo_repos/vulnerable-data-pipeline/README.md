# vulnerable-data-pipeline

> **⚠️ INTENTIONALLY VULNERABLE** — This repository is a demo target for
> [Sentinel](https://github.com/anupamojha-eng/agentic-remediation-factory),
> an autonomous CVE remediation agent. Do **not** deploy this code.

A realistic Python data-ingestion service with **5 known CVEs across 4
packages** — and dangerous source-code patterns in 2 files — designed to
demonstrate Sentinel's multi-layer remediation capability.

---

## Vulnerability surface

| GHSA | Package | Version | Severity | Type |
|------|---------|---------|----------|------|
| [GHSA-8q59-q68h-6hv4](https://github.com/advisories/GHSA-8q59-q68h-6hv4) | PyYAML | 5.3.1 | **Critical** | RCE via `yaml.load()` |
| [GHSA-6q5r-27gj-jm84](https://github.com/advisories/GHSA-6q5r-27gj-jm84) | PyYAML | 5.3.1 | **Critical** | RCE in `full_load` |
| [GHSA-v8gr-m533-ghj9](https://github.com/advisories/GHSA-v8gr-m533-ghj9) | cryptography | 3.3.2 | **High** | RSA decryption oracle |
| [GHSA-j8r2-6x86-q33q](https://github.com/advisories/GHSA-j8r2-6x86-q33q) | requests | 2.27.0 | **Medium** | Auth headers leaked on redirect |
| [GHSA-q2q7-5pp4-w6pg](https://github.com/advisories/GHSA-q2q7-5pp4-w6pg) | urllib3 | 1.24.1 | **Medium** | Header injection via CRLF |

Plus a **CWE-502 (unsafe deserialization)** pattern in `app/cache.py` that
Sentinel flags proactively regardless of specific GHSA IDs.

---

## What Sentinel does

```
1. Fork this repo
2. Clone into an isolated Docker sandbox
3. Resolve full dependency tree (pip install → pip list)
4. Query OSV batch API for PyPI ecosystem → finds all 5 GHSAs
5. Grep source tree for yaml.load( and pickle.loads( patterns
6. Call Gemini 2.5 Flash to generate patches for:
     requirements.txt   — bump 4 packages to safe minimums
     app/config.py      — yaml.load() → yaml.safe_load() (3 call sites)
     app/cache.py       — pickle.loads() replaced or guarded (4 call sites)
7. Verify: pip install -r requirements.txt && python3 -m pytest -q
8. Open a pull request with diff + GHSA references
```

This is **more complex than the Java demo** (excel-streaming-reader):
- 5 CVEs vs 2 for Java
- 3 files patched vs 1–2 for Java
- Source patching is **proactive** (triggered by grep, not a compile error)
- Tests run in the sandbox as part of verification

---

## Project structure

```
app/
  config.py     ← yaml.load() — needs source fix (3 call sites)
  cache.py      ← pickle.loads() — needs source fix (4 call sites)
  ingestor.py   ← requests + Pillow — fixed via requirements.txt only
  api.py        ← Flask REST API
tests/
  test_config.py
  test_cache.py
  test_ingestor.py
config/
  settings.yaml
requirements.txt  ← 7 packages, 5 known CVEs
```

---

## Running Sentinel against this repo

```bash
# Set up credentials
export GITHUB_TOKEN=<your PAT with repo + fork scope>
export GEMINI_API_KEY=<your Gemini API key>

# Run
cd agentic-remediation-factory
python orchestrator/driver.py  # or POST to the FastAPI endpoint
```

Or via the REST API:

```bash
curl -X POST http://localhost:8080/remediate \
  -H 'Content-Type: application/json' \
  -d '{"repo_url": "https://github.com/YOUR_ORG/vulnerable-data-pipeline",
       "target_tag": "main"}'
```

Sentinel will open a PR on this repo within ~3 minutes.
