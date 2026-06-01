# Contributing to Sentinel

Thank you for your interest in contributing.

## Development setup

```bash
git clone https://github.com/anupamojha-eng/agentic-remediation-factory
cd agentic-remediation-factory
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Add GITHUB_TOKEN and GEMINI_API_KEY to .env
```

Build the sandbox image (required for Docker-based tests):

```bash
docker build -t cve-fixer-sandbox:latest sandbox/
```

## Test tiers

| Tier | Command | Needs |
|---|---|---|
| Unit | `pytest tests/test_python_support.py tests/test_patching.py tests/test_build_detection.py` | Nothing |
| Docker e2e | `pytest tests/test_e2e_docker.py tests/test_e2e_python_docker.py -v -s` | Docker + `GEMINI_API_KEY` |
| Source patching | `pytest tests/test_java_source_patching_e2e.py tests/test_python_source_patching_e2e.py -v -s` | Docker + `GEMINI_API_KEY` |
| Real repo | `pytest tests/test_real_repo_e2e.py tests/test_real_python_repo_e2e.py -v -s` | Docker + both keys |

Always run the unit tests before submitting a PR. Docker e2e tests are run in CI on merge.

## Adding a new ecosystem

1. Add detection in `factory._detect_build_system()`
2. Add dependency resolution in `factory._resolve_all_dependencies()`
3. Add ecosystem name to `factory._ECOSYSTEM`
4. Add verify command in `factory._get_verify_command()`
5. Add source file extension in `remediator.get_vulnerable_code_files()`
6. Add known patterns in `llm_client.SecurityAgentClient._KNOWN_PATTERNS`
7. Add a fixture in `tests/fixtures/` and a Docker e2e test class

## Pull request guidelines

- Keep PRs focused — one feature or fix per PR
- All unit tests must pass
- New ecosystem support requires a Docker e2e test
- Do not commit `.env`, secrets, or `temp_repos/`
