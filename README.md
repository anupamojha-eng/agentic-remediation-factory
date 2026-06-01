# Sentinel — Autonomous CVE Remediation

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Ecosystems](https://img.shields.io/badge/ecosystems-Java%20%7C%20Python-green.svg)](#supported-ecosystems)

**Sentinel closes the "last mile" of CVE remediation.**  
Most tools tell you what's vulnerable. Sentinel fixes it — opening a verified, build-passing pull request with no human in the loop.

```
CVE detected → fork repo → resolve full dep tree → query OSV →
patch build files + source code → verify build in sandbox → open PR
```

**Live demo PRs opened by Sentinel:**
- Java: [monitorjbl/excel-streaming-reader#271](https://github.com/monitorjbl/excel-streaming-reader/pull/271) — Log4Shell + Apache POI CVEs, `pom.xml` + Java source patched
- Python: [vulnerable-data-pipeline](https://github.com/anupamojha-eng/vulnerable-data-pipeline) — 5 PyPI CVEs, `requirements.txt` + `config.py` + `cache.py` patched

---

## Why this is different

| Tool | Detects | Patches build file | Patches source code | Verifies build | Opens PR |
|---|---|---|---|---|---|
| Dependabot | ✅ | ✅ | ❌ | ❌ | ✅ |
| Snyk | ✅ | Partial | ❌ | ❌ | ✅ |
| Renovate | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Sentinel** | ✅ | ✅ | ✅ | ✅ | ✅ |

Dependabot bumps versions. Sentinel bumps versions *and* fixes the dangerous call sites in your code (`yaml.load()` → `yaml.safe_load()`, `enableDefaultTyping` removal, etc.) — then proves the build still passes before touching your repo.

---

## What Sentinel does

### Three-layer remediation

**Layer 1 — Transitive CVE detection**  
Resolves the *complete* dependency tree (not just declared deps) using the native build tool, then queries the OSV REST API for every package including transitively pulled dependencies. Catches CVEs that arrive silently through frameworks — e.g. `snakeyaml` via Spring Boot, `urllib3` via `requests`.

**Layer 2 — Build file patching**  
LLM upgrades `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml`, `requirements.txt`, and `pyproject.toml` to the minimum safe version. Handles version variables, BOM imports, Kotlin DSL, and Gradle version catalogs.

**Layer 3 — Source code patching (proactive + reactive)**  
Greps source files for dangerous call-site patterns tied to the found CVEs:

- **Proactive (Python):** `yaml.load()` → `yaml.safe_load()`, `pickle.loads()` guarded — fires *before* any runtime error, on the first pass
- **Reactive (Java):** when a library API change breaks compilation (e.g. POI 5.0→5.2 removes a method), Sentinel reads the failing `.java` files and implements the fix, then retries the build

### Verify before merge

Every patch is tested in an isolated Docker sandbox (JDK 17 + Maven/Gradle, Python 3 + pip) before the PR is opened. If the build fails, Sentinel extracts the error, feeds it back to the LLM, and retries up to 3 times. A PR is only opened when `mvn clean compile` / `pip install && pytest` exits 0.

---

## Supported ecosystems

| Build system | Detection | Transitive scan | Source patching | Verify command |
|---|---|---|---|---|
| Maven (`pom.xml`) | ✅ | `mvn dependency:list` | ✅ `.java` | `mvn clean compile` |
| Gradle Groovy | ✅ | `gradle dependencies` | ✅ `.java` | `gradle compileJava` |
| Gradle KTS | ✅ | `gradle dependencies` | ✅ `.java` | `gradle compileJava` |
| Gradle version catalog | ✅ | `gradle dependencies` | ✅ `.java` | `gradle compileJava` |
| `requirements.txt` | ✅ | `pip install` + `pip list` | ✅ `.py` | `pip install && pip check` |
| `pyproject.toml` | ✅ | `pip install` + `pip list` | ✅ `.py` | `pip install && pytest` |

---

## Quick start

```bash
# 1. Clone and install
git clone https://github.com/anupamojha-eng/agentic-remediation-factory
cd agentic-remediation-factory
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Set credentials
cp .env.example .env
# Edit .env — add GITHUB_TOKEN and at least one LLM key:
#   ANTHROPIC_API_KEY  (Claude — recommended, best accuracy)
#   GEMINI_API_KEY     (Gemini Flash — cost-effective alternative)
# Both keys can coexist; Anthropic is preferred when both are set.

# 3. Build the sandbox image (one-time, ~5 min)
docker build -t cve-fixer-sandbox:latest sandbox/

# 4. Run against any public repo
python3 orchestrator/driver.py  # starts the FastAPI service

curl -X POST http://localhost:8080/remediate \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/anupamojha-eng/vulnerable-data-pipeline",
       "target_tag": "main"}'
```

Sentinel forks the repo, opens a sandbox container, scans, patches, verifies, and opens a PR — typically in under 3 minutes.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    orchestrator/                         │
│                                                         │
│  driver.py        FastAPI service — HTTP entry point    │
│  factory.py       RemediationFactory                    │
│    ├─ _detect_build_system()   Maven/Gradle/Python      │
│    ├─ _scan_internal()         resolve deps → OSV API   │
│    │    └─ _scan_with_osv_scanner()  fallback           │
│    ├─ _get_verify_command()    build tool selector      │
│    └─ retry loop (MAX=3)       smart error routing      │
│                                                         │
│  remediator.py    RemediationActor                      │
│    ├─ get_vulnerable_code_files()  grep → source files  │
│    ├─ get_affected_java_files()    parse compile errors  │
│    ├─ autonomous_patch()           LLM → write → verify │
│    └─ create_pull_request()        branch → push → PR   │
│                                                         │
│  llm_client.py    SecurityAgentClient                   │
│    ├─ _AnthropicProvider  Claude Opus 4.8 (default)     │
│    ├─ _GeminiProvider     Gemini 2.5 Flash (alt)        │
│    ├─ get_vulnerable_patterns()    CVE → grep strings   │
│    └─ get_remediation_plan()       full patch plan      │
└─────────────────────────────────────────────────────────┘
                           │
                           │ Docker SDK
                           ▼
┌─────────────────────────────────────────────────────────┐
│               sandbox/  (Docker image)                   │
│                                                         │
│  JDK 17 · Maven 3.9 · Gradle 9.4 · OSV-Scanner         │
│  Python 3 · pip3 · git                                  │
│                                                         │
│  Isolated per-run: no shared state between remediations │
└─────────────────────────────────────────────────────────┘
```

---

## Running tests

```bash
# Fast unit tests (no Docker, no API keys)
pytest tests/test_python_support.py tests/test_patching.py \
       tests/test_build_detection.py tests/test_scanner.py -v

# Docker e2e — Java (needs Docker + ANTHROPIC_API_KEY or GEMINI_API_KEY)
pytest tests/test_e2e_docker.py -v -s

# Docker e2e — Python (needs Docker + ANTHROPIC_API_KEY or GEMINI_API_KEY)
pytest tests/test_e2e_python_docker.py -v -s

# Source patching — Java multi-file (needs Docker + ANTHROPIC_API_KEY or GEMINI_API_KEY)
pytest tests/test_java_source_patching_e2e.py -v -s

# Source patching — Python multi-file (needs Docker + ANTHROPIC_API_KEY or GEMINI_API_KEY)
pytest tests/test_python_source_patching_e2e.py -v -s

# Full pipeline — real GitHub repo (needs Docker + ANTHROPIC_API_KEY or GEMINI_API_KEY + GITHUB_TOKEN)
pytest tests/test_real_repo_e2e.py -v -s          # Java
pytest tests/test_real_python_repo_e2e.py -v -s   # Python
```

---

## Demo repository

[`vulnerable-data-pipeline`](demo_repos/vulnerable-data-pipeline/) — a realistic Flask data-ingestion service with 5 known CVEs and dangerous source patterns in 2 files. Push it to GitHub to use as your own Sentinel test target.

| File | Issue |
|---|---|
| `requirements.txt` | PyYAML 5.3.1, cryptography 3.3.2, requests 2.27.0, urllib3 1.24.1 |
| `app/config.py` | `yaml.load()` — 3 call sites (RCE vector) |
| `app/cache.py` | `pickle.loads()` — 4 call sites (deserialization RCE) |

Sentinel patches all three files in a single PR.

---

## Technical Stack

- **Orchestrator**: Python / FastAPI — manages container lifecycle, retry loop, GitHub API
- **Sandbox**: Docker (JDK 17, Maven 3.9.15, Gradle 9.4.1, OSV-Scanner, Python 3 + pip)
- **Scanning**: `mvn dependency:list` / `gradle dependencies` / `pip list` + OSV REST API; OSV-Scanner (fallback)
- **Reasoning**: Multi-provider — Anthropic Claude (default) or Google Gemini
- **Version control**: PyGithub — fork, branch, commit, PR

### LLM provider comparison

| | Claude Opus 4.8 (default) | Gemini 2.5 Flash |
|---|---|---|
| Complex multi-file patches | Excellent | Good |
| JSON output reliability | Excellent | Good |
| Prompt caching on retries | Yes (~80% savings) | No |
| Speed | Moderate | Fast |
| Cost per run | Higher | Lower |

Set `ANTHROPIC_API_KEY` for Claude, `GEMINI_API_KEY` for Gemini, or both (Claude wins when both set).  
Override with `ANTHROPIC_MODEL=claude-sonnet-4-6` or `GEMINI_MODEL=gemini-2.5-pro`.

---

## Roadmap

- [ ] Go (`go.mod`) and Rust (`Cargo.toml`) ecosystem support
- [ ] SBOM input (CycloneDX / SPDX) for repos without a build tool available
- [ ] GitHub Actions integration — trigger on Dependabot alert webhook
- [ ] Container image scanning — pair with Chainguard Wolfi or distroless base images
- [ ] Web dashboard for PR status and audit trail

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability disclosure policy.

## License

Apache License 2.0 — see [LICENSE](LICENSE).  
Copyright 2026 Anupam Ojha
