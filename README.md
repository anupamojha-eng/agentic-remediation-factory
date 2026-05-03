# Sentinel: Agentic Security Remediation

**Sentinel** is an autonomous platform engineer designed to handle the "last mile" of security compliance: the automated remediation of library vulnerabilities. While many tools identify vulnerabilities, Sentinel focuses on the practical execution of patching, specifically targeting the **automated upgrade and verification of Maven dependencies** without manual intervention.

---

## ⚙️ Prerequisites & Environment Setup

To run the remediation factory, you must export the following environment variables. These allow the agent to authenticate with GitHub, interact with the LLM, and track execution via telemetry.

| Variable | Description |
| :--- | :--- |
| `GITHUB_TOKEN` | Personal Access Token (PAT) with `repo` scope to push branches and create PRs. |
| `GEMINI_API_KEY` | API key for the Gemini 2.5 Flash model used for reasoning and plan generation. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (Optional) The endpoint for your OpenTelemetry collector to ingest metrics. |
```bash
export GITHUB_TOKEN="your_github_token"
export GEMINI_API_KEY="your_gemini_key"

---

## 🚀 The Crux: Core Functionality

The core value of Sentinel lies in its ability to navigate the complexities of a real-world build environment to achieve a clean, verified patch. It does not just change a version string; it ensures the project actually builds.

*   **Autonomous Version Resolution**: Uses Gemini 2.5 Flash to analyze `pom.xml` files and determine the safest, most compatible version upgrades for identified GHSA/CVE IDs.
*   **Environment Adaptation**: Detects build failures caused by environment mismatches (e.g., Java version conflicts) and applies "deep patches" to the `pom.xml` (source/target levels, compiler args) to ensure compilation.
*   **Verified PR Lifecycle**:
    *   **Scan**: Identifies vulnerabilities in the target repository.
    *   **Patch**: Modifies `pom.xml` via Python-based XML manipulation.
    *   **Verify**: Runs `mvn clean compile` within an isolated Docker sandbox to ensure no regressions.
    *   **Publish**: Pushes a new branch and opens a Pull Request to the dynamically resolved default branch (e.g., `3.x` or `main`).

---

## 📊 Observability & Telemetry

Sentinel is built with native **OpenTelemetry** integration to provide deep insights into the remediation process. Every execution exports metrics to help tune the agent:

*   **LLM Latency**: Tracking the reasoning time for the Gemini model.
*   **Token Economics**: Monitoring prompt and completion usage to optimize costs.
*   **Build Success Rates**: Quantifying the reliability of autonomous environment fixes.

---

## 🛠️ Technical Stack

*   **Orchestrator**: Python-based driver managing the end-to-end remediation loop.
*   **Sandbox**: Isolated Docker environments for safe, side-effect-free build verification.
*   **Reasoning**: Gemini 2.5 Flash for context-aware dependency management.
*   **Version Control**: PyGithub integration for automated PR lifecycle management.

---

## 📖 Usage

To trigger the autonomous remediation factory:
```bash
python3 orchestrator/driver.py