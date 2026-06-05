# Sentinel — Autonomous CVE Remediation

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/sentinel-remediation.svg)](https://pypi.org/project/sentinel-remediation/)
[![Ecosystems](https://img.shields.io/badge/ecosystems-Java%20%7C%20Python-green.svg)](#supported-ecosystems)

**Sentinel closes the "last mile" of CVE remediation.**  
Most tools tell you what's vulnerable. Sentinel fixes it — opening a verified, build-passing pull request with no human in the loop.

```
CVE detected → fork repo → resolve full dep tree → query OSV →
patch build files + source code → verify build in sandbox → open PR
```

**Live demo PRs opened by Sentinel:**
- Java: [monitorjbl/excel-streaming-reader#271](https://github.com/monitorjbl/excel-streaming-reader/pull/271) — Log4Shell + Apache POI CVEs, `pom.xml` + Java source patched
- Python: [vulnerable-data-pipeline#2](https://github.com/anupamojha-eng/vulnerable-data-pipeline/pull/2) — 5 PyPI CVEs, `requirements.txt` + `config.py` + `cache.py` patched

---

## Install

```bash
pip install sentinel-remediation
```

Requires Docker running locally. Set credentials in a `.env` file (see [Quick start](#quick-start)).

---

## Usage

```bash
# Fix CVEs in any public GitHub repo
sentinel fix-cve --repo https://github.com/org/repo

# Target a specific branch
sentinel fix-cve --repo https://github.com/org/repo --branch develop

# Force a specific LLM provider
sentinel fix-cve --repo https://github.com/org/repo --llm gemini

# Override the model
sentinel fix-cve --repo https://github.com/org/repo --llm anthropic --model claude-sonnet-4-6
```

Sentinel forks the repo, opens a sandbox container, scans, patches, verifies, and opens a PR — typically in under 3 minutes.

---

## Why this is different

| Tool | Detects | Patches build file | Patches source code | Verifies build | Opens PR |
|---|---|---|---|---|---|
| Dependabot | ✅ | ✅ | ❌ | ❌ | ✅ |
| Snyk | ✅ | Partial | ❌ | ❌ | ✅ |
| Renovate | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Sentinel** | ✅ | ✅ | ✅ | ✅ | ✅ |

Dependabot bumps versions. Sentinel bumps versions *and* fixes the dangerous call sites in your code — then proves the build still passes before touching your repo.

---

## What Sentinel does

### Three-layer remediation

**Layer 1 — Transitive CVE detection**  
Resolves the *complete* dependency tree (not just declared deps) using the native build tool, then queries the OSV REST API for every package including transitively pulled dependencies. Catches CVEs that arrive silently through frameworks.

**Layer 2 — Build file patching**  
LLM upgrades `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml`, `requirements.txt`, and `pyproject.toml` to the minimum safe version. Handles version variables, BOM imports, Kotlin DSL, and Gradle version catalogs.

**Layer 3 — Source code patching**  
Greps source files for dangerous call-site patterns — both CVE-specific and a built-in set of always-checked anti-patterns:

**Python anti-patterns (always checked):**
| Pattern | Risk |
|---------|------|
| `yaml.load(` | RCE via unsafe deserialization |
| `pickle.loads(` / `pickle.load(` | RCE via deserialization |

**Java anti-patterns (always checked):**
| Pattern | Risk |
|---------|------|
| `new ObjectInputStream(` | Java deserialization RCE |
| `Runtime.getRuntime().exec(` | OS command injection |
| `new ProcessBuilder(` | OS command injection |
| `MessageDigest.getInstance("MD5"` | Weak hashing |
| `MessageDigest.getInstance("SHA-1"` | Weak hashing |
| `new Random(` | Insecure randomness |
| `DocumentBuilderFactory.newInstance(` | XML External Entity (XXE) |
| `XMLInputFactory.newInstance(` | XML External Entity (XXE) |

### PR audit trail

Every PR opened by Sentinel includes a structured evidence trail:
- CVEs addressed
- Files changed with patterns found
- Build verification status and attempt count
- Truncated build output (collapsible)
- Timestamp

### Verify before merge

Every patch is tested in an isolated Docker sandbox (JDK 17 + Maven/Gradle, Python 3 + pip) before the PR is opened. If the build fails, Sentinel extracts the error, feeds it back to the LLM, and retries up to 3 times.

### Fallback when PR can't be opened

If the GitHub API is unavailable or rate-limited, Sentinel extracts the diff from the container and saves it as `sentinel-patch-<timestamp>.diff` locally with apply instructions. The fix is never lost.

---

## Supported ecosystems

| Build system | Detection | Transitive scan | Source patching | Verify command |
|---|---|---|---|---|
| Maven (`pom.xml`) | ✅ | `mvn dependency:list` | ✅ `.java` | `mvn clean compile` |
| Gradle Groovy | ✅ | `gradle dependencies` | ✅ `.java` | `gradle compileJava` |
| Gradle KTS | ✅ | `gradle dependencies` | ✅ `.java` | `gradle compileJava` |
| Gradle version catalog | ✅ | `gradle dependencies` | ✅ `.java` | `gradle compileJava` |
| `requirements.txt` | ✅ | `pip install` + `pip list` | ✅ `.py` | `pip install && pytest` |
| `pyproject.toml` | ✅ | `pip install` + `pip list` | ✅ `.py` | `pip install && pytest` |

---

## Quick start

```bash
# 1. Install
pip install sentinel-remediation

# 2. Set credentials
cp .env.example .env
# Edit .env — add GITHUB_TOKEN and at least one LLM key:
#   ANTHROPIC_API_KEY  (Claude — recommended, best accuracy)
#   GEMINI_API_KEY     (Gemini Flash — cost-effective alternative)

# 3. Build the sandbox image (one-time, ~5 min)
docker build -t cve-fixer-sandbox:latest sandbox/

# 4. Run
sentinel fix-cve --repo https://github.com/anupamojha-eng/vulnerable-data-pipeline
```

### Running via API (FastAPI server)

```bash
python3 orchestrator/driver.py  # starts on :8080

curl -X POST http://localhost:8080/remediate \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/org/repo", "target_tag": "main"}'
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    orchestrator/                         │
│                                                         │
│  cli.py           `sentinel` CLI entry point            │
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
│    ├─ create_pull_request()        branch → push → PR   │
│    ├─ _build_pr_body()             audit trail          │
│    └─ _patch_fallback()            save diff locally    │
│                                                         │
│  llm_client.py    SecurityAgentClient                   │
│    ├─ _AnthropicProvider  Claude Opus 4.8 (default)     │
│    ├─ _GeminiProvider     Gemini 2.5 Flash (alt)        │
│    ├─ get_vulnerable_patterns()    CVE → grep strings   │
│    └─ get_remediation_plan()       full patch plan      │
│                                                         │
│  telemetry.py     Observability                         │
│    ├─ setup_telemetry()   OTLP or console export        │
│    ├─ TokenUsageTracker   per-run token + cost report   │
│    └─ record_llm_tokens() OTel counters + cost tracker  │
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

# Docker e2e — needs Docker + LLM key
pytest tests/test_e2e_docker.py -v -s              # Java
pytest tests/test_e2e_python_docker.py -v -s       # Python

# Source patching e2e
pytest tests/test_java_source_patching_e2e.py -v -s
pytest tests/test_python_source_patching_e2e.py -v -s

# Full pipeline — needs Docker + LLM key + GITHUB_TOKEN
pytest tests/test_real_repo_e2e.py -v -s           # Java
pytest tests/test_real_python_repo_e2e.py -v -s    # Python
```

---

## Observability

Every run emits OTel traces and metrics. Set `OTEL_EXPORTER_OTLP_ENDPOINT` to ship to any backend (Grafana, Datadog, Honeycomb). Defaults to console output if not set.

### Traces

| Span | Attributes |
|------|-----------|
| `sentinel.remediation` | `repo`, `branch`, `build_system`, `cve_count`, `pr_url` |
| `sentinel.scan` | `cve_count`, `cves` |
| `sentinel.patch` | `attempt` |
| `sentinel.llm_call` | `stage`, `model` |
| `sentinel.verify` | `attempt`, `exit_code` |
| `sentinel.pr_create` | `pr_url`, `success` |

### Metrics

| Metric | Type | Tags |
|--------|------|------|
| `sentinel.remediation_duration_seconds` | histogram | `build_system` |
| `sentinel.scan_duration_seconds` | histogram | `build_system` |
| `sentinel.verify_duration_seconds` | histogram | `build_system`, `attempt` |
| `sentinel.cves_found_total` | counter | `build_system` |
| `sentinel.patch_attempts_total` | counter | `build_system`, `attempt` |
| `sentinel.pr_opened_total` | counter | `build_system`, `success` |
| `sentinel.llm_tokens_total` | counter | `model`, `stage`, `repo`, `type` |
| `sentinel.llm_cost_usd_total` | counter | `model`, `stage`, `repo` |

### Token & cost report

Printed at the end of every run — shows per-stage token usage, cache hits, cache savings in dollars, and total cost:

```
════════════════════════════════════════════════════════════════════════════════
  Sentinel Token & Cost Report
  Repo: https://github.com/org/repo
════════════════════════════════════════════════════════════════════════════════
  Stage                  Model                        In    Out  Cache↓  Cache↑     Cost
  ──────────────────────────────────────────────────────────────────────────────
  pattern_detect         claude-opus-4-8            1,234    89       —       —  $0.0185
  patch                  claude-opus-4-8           12,456   823       —   8,234  $0.0234
                         cache saved:                                            -$0.1235
  ──────────────────────────────────────────────────────────────────────────────
  TOTAL                                            13,690   912       —   8,234  $0.0419
  Cache savings:....................................                      -$0.1235
  Net cost (after savings):.........................                       $0.0419
════════════════════════════════════════════════════════════════════════════════
```

Cache↓ = tokens read from cache · Cache↑ = tokens written to cache

---

## Technical stack

- **CLI**: Click — `sentinel fix-cve --repo <url>`
- **Orchestrator**: Python / FastAPI — container lifecycle, retry loop, GitHub API
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

- [ ] `sentinel fix-antipatterns` — standalone anti-pattern fixing without a CVE trigger
- [ ] Local LLM mode — Ollama + quantized model for air-gapped / zero-cost runs
- [ ] OSV offline cache — local SQLite built from OSV data dumps, no API calls
- [ ] Go (`go.mod`) and Rust (`Cargo.toml`) ecosystem support
- [ ] GitHub Actions integration — trigger on Dependabot alert webhook
- [ ] Container image scanning — pair with Chainguard Wolfi or distroless base images

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability disclosure policy.

## License

Apache License 2.0 — see [LICENSE](LICENSE).  
Copyright 2026 Anupam Ojha
