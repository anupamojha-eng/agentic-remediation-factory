"""
Full end-to-end test against a real public GitHub repository.

Target: monitorjbl/excel-streaming-reader
  - log4j-core 2.14.1 (test scope) → Log4Shell family (GHSA-jfh8-c2jp-hdp8 etc.)
  - apache.poi 5.0.0               → several known CVEs

Flow: fork → clone → scan (OSV-Scanner) → patch (Gemini) → verify (mvn) → PR

Requirements: Docker running, GEMINI_API_KEY, GITHUB_TOKEN

Run: pytest tests/test_real_repo_e2e.py -v -s
"""
import os
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "orchestrator"))

TARGET_REPO = "https://github.com/monitorjbl/excel-streaming-reader"
TARGET_BRANCH = "master"


@pytest.fixture(scope="module", autouse=True)
def require_env():
    missing = [v for v in ("GEMINI_API_KEY", "GITHUB_TOKEN") if not os.getenv(v)]
    if missing:
        pytest.skip(f"Missing env vars: {missing}")
    try:
        import docker
        docker.from_env().ping()
    except Exception as exc:
        pytest.skip(f"Docker unavailable: {exc}")


def test_fork_scan_patch_verify_pr():
    """
    Drives the full Sentinel pipeline against a real vulnerable repo:
    fork → clone at branch → detect Maven → OSV-Scanner finds CVEs →
    Gemini patches pom.xml → mvn clean compile passes → PR opened.
    """
    from factory import RemediationFactory

    factory = RemediationFactory()
    print(f"\nTarget: {TARGET_REPO} @ {TARGET_BRANCH}")

    pr_url = factory.execute_ephemeral_fix(TARGET_REPO, TARGET_BRANCH)

    assert pr_url is not None, (
        "execute_ephemeral_fix returned None — PR was not created. "
        "Check stdout above for the failure step."
    )
    print(f"\nPR created: {pr_url}")
