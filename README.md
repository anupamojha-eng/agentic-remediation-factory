# Sentinel: Agentic Security Remediation

**Sentinel** is an autonomous platform engineer designed to handle the "last mile" of security compliance: the automated remediation of library vulnerabilities including **transitive dependencies** and **vulnerable code patterns**. It identifies CVEs, patches build files, fixes Java source code where required, verifies the build inside an isolated sandbox, and opens a verified Pull Request — with no human intervention.

---

## What Sentinel Does

### Three-layer fix strategy

| Layer | Description |
| :--- | :--- |
| **Transitive dependency detection** | Resolves the complete dependency tree (`mvn dependency:list` / `gradle dependencies`) and queries the OSV REST API for ALL vulnerabilities — not just declared deps. Catches CVEs that arrive silently through framework transitive dependencies (e.g. snakeyaml via Spring Boot). |
| **Build file patching** | LLM-driven: upgrades `pom.xml`, `build.gradle`, `build.gradle.kts`, and `gradle/libs.versions.toml` to the minimum safe version. Handles direct versions, version variables, Kotlin DSL, BOM imports, and version catalogs. |
| **Java source code patching** | When the LLM identifies an exploitable code pattern (e.g. `new Yaml()` for CVE-2022-1471, `enableDefaultTyping` for Jackson CVEs), it greps the source tree and patches the vulnerable call sites alongside the build file. Also fixes compile-time breaks caused by API changes in upgraded libraries. |

### End-to-end verified flow

```
POST /remediate { repo_url, target_tag }
  ↓
Fork upstream repo on GitHub
  ↓
Launch isolated Docker sandbox (JDK 17, Maven 3.9, Gradle 9.4, OSV-Scanner)
  ↓
Clone fork → resolve full dep tree → OSV API → find all CVEs (direct + transitive)
  ↓
LLM scans source tree for exploitable patterns → includes matching .java files
  ↓
Gemini 2.5 Flash patches: build file + any vulnerable Java call sites
  ↓
mvn clean compile / ./gradlew compileJava (build verified in sandbox)
  ↓
If compile fails: LLM reads failing .java files → fixes API incompatibilities → retry
  ↓
Push branch → open Pull Request against upstream
  ↓
Destroy sandbox container
```

---

## Prerequisites & Environment Setup

| Variable | Description |
| :--- | :--- |
| `GITHUB_TOKEN` | Personal Access Token with `repo` scope — forks repos and opens PRs. |
| `GEMINI_API_KEY` | API key for Gemini 2.5 Flash — reasoning, plan generation, code patching. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (Optional) OpenTelemetry collector endpoint for metrics. |

```bash
export GITHUB_TOKEN="your_github_token"
export GEMINI_API_KEY="your_gemini_key"
```

---

## Usage

```bash
# Start the FastAPI service
python3 orchestrator/driver.py

# Trigger remediation
curl -X POST http://localhost:8080/remediate \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo", "target_tag": "main"}'
```

---

## Proven Capabilities

### Task 1 — Maven & Gradle support
All five real-world build patterns verified with real Gemini API calls:
- Maven `<dependency>` version tags and `<properties>` version variables
- Gradle Groovy DSL direct versions and `ext {}` version variables
- Gradle Kotlin DSL
- Gradle version catalogs (`gradle/libs.versions.toml`)

### Task 2 — Java source code changes
When upgrading a library changes its API, Sentinel reads the failing Java files and implements the required fixes:
- Missing abstract method stubs (e.g. new interface methods added in POI 5.2.x)
- Type cast corrections (e.g. `SharedStrings` interface change)
- Missing imports

### Transitive CVE detection + exploitable code patching
The full demo scenario:
- Spring Boot 2.5.6 pulls in `snakeyaml:1.28` transitively (not declared in `pom.xml`)
- `ConfigLoader.java` calls `new Yaml().load(untrustedInput)` — the exploitable pattern for CVE-2022-1471
- Sentinel: detects snakeyaml via full dep tree scan → finds ConfigLoader.java via pattern search → patches both pom.xml (version override) and the Java code (adds `SafeConstructor`)
- Demo repo: `https://github.com/anupamojha-eng/sentinel-transitive-cve-demo`

### Retry loop with error feedback
If the first upgrade attempt breaks the build, Sentinel extracts the compile errors, feeds them back to the LLM, and retries up to 3 times. Java-only compile errors preserve the already-upgraded build file; parse errors restore it.

---

## Observability

Native OpenTelemetry integration:
- **LLM latency** histogram per model
- **Token usage** counters (prompt / completion)
- **Build success rate** visible from retry counts in logs

---

## Technical Stack

- **Orchestrator**: Python / FastAPI — manages container lifecycle, retry loop, GitHub API
- **Sandbox**: Docker (JDK 17, Maven 3.9.15, Gradle 9.4.1, OSV-Scanner)
- **Scanning**: `mvn dependency:list` / `gradle dependencies` + OSV REST API (transitive); OSV-Scanner (fallback)
- **Reasoning**: Gemini 2.5 Flash (build file patching, code pattern detection, Java source fixes)
- **Version control**: PyGithub — fork, branch, commit, PR

---

## Known Limitations

### Gradle transitive dependency scanning
Gradle transitive CVE detection has limited support:

- **What works**: If the project has a committed `gradle.lockfile`, OSV-Scanner reads it and detects transitive CVEs.
- **What doesn't work**: Projects without a `gradle.lockfile` — the `gradle dependencies` fallback requires the project to be resolvable (valid Gradle setup, internet access inside sandbox, no missing plugins). It often fails on first run.
- **Recommended path**: Add the [CycloneDX Gradle plugin](https://github.com/CycloneDX/cyclonedx-gradle-plugin) to your build and generate an SBOM. OSV-Scanner supports `--sbom` directly. This is not yet automated in Sentinel.
- **Maven** has no such limitation: `mvn dependency:list` reliably resolves the full tree.

### Exploitable pattern detection accuracy
The pattern search relies on the LLM knowing which code patterns make a CVE exploitable. For well-known CVEs (Log4Shell, Text4Shell, SnakeYAML deserialization) this works well. For obscure CVEs, the LLM may return no patterns and only the build file gets upgraded.

### Multi-module Maven/Gradle projects
The scanner and patcher operate on the root build file. Multi-module projects where the vulnerable dependency or exploitable code is in a submodule are not yet handled.
