"""
Full end-to-end test against the vulnerable-data-pipeline demo repo on GitHub.

Target: github.com/anupamojha-eng/vulnerable-data-pipeline
  - PyYAML 5.3.1     → GHSA-8q59-q68h-6hv4 (RCE via yaml.load)
  - cryptography 3.3.2 → GHSA-v8gr-m533-ghj9 (RSA oracle)
  - requests 2.27.0  → GHSA-j8r2-6x86-q33q (auth header leak)
  - urllib3 1.24.1   → GHSA-q2q7-5pp4-w6pg (header injection)
  - Pillow 8.4.0     → multiple image-decoder CVEs
  - app/config.py    → yaml.load() (3 call sites, patched to yaml.safe_load)
  - app/cache.py     → pickle.loads() (4 call sites, replaced/guarded)

Flow: fork → clone → scan (OSV API + file fallback) → patch build + sources
      (Claude or Gemini) → verify (pip install + pytest) → open PR

This test is MORE complex than the Java real-repo test (test_real_repo_e2e.py):
  5 GHSAs vs 2 │ 3 patched files vs 1 │ source fixes are proactive, not error-driven

Requirements:
  - Docker running
  - ANTHROPIC_API_KEY (Claude, recommended) or GEMINI_API_KEY (Gemini)
  - GITHUB_TOKEN set (repo + fork scope)
  - demo repo pushed to GitHub: demo_repos/vulnerable-data-pipeline/

Run: pytest tests/test_real_python_repo_e2e.py -v -s
"""
import os
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "orchestrator"))

TARGET_REPO = "https://github.com/anupamojha-eng/vulnerable-data-pipeline"
TARGET_BRANCH = "main"


@pytest.fixture(scope="module", autouse=True)
def require_env():
    if not os.getenv("ANTHROPIC_API_KEY") and not os.getenv("GEMINI_API_KEY"):
        pytest.skip("Set ANTHROPIC_API_KEY (Claude) or GEMINI_API_KEY (Gemini)")
    if not os.getenv("GITHUB_TOKEN"):
        pytest.skip("Missing env var: GITHUB_TOKEN")
    try:
        import docker
        docker.from_env().ping()
    except Exception as exc:
        pytest.skip(f"Docker unavailable: {exc}")


def test_fork_scan_patch_verify_pr():
    """
    Drives the full Sentinel pipeline against the vulnerable-data-pipeline demo:

      fork → clone → detect Python (requirements.txt) →
      OSV transitive scan (PyPI ecosystem) finds ≥4 GHSAs →
      LLM patches requirements.txt + app/config.py + app/cache.py →
      pip install + pytest pass in sandbox →
      PR opened on the upstream repo.

    Expected PR diff:
      - requirements.txt: 4 version bumps (PyYAML, cryptography, requests, urllib3)
      - app/config.py:    yaml.load() → yaml.safe_load() (3 sites)
      - app/cache.py:     pickle.loads() replaced or guarded (4 sites)
    """
    from factory import RemediationFactory

    factory = RemediationFactory()
    print(f"\nTarget: {TARGET_REPO} @ {TARGET_BRANCH}")

    pr_url = factory.execute_ephemeral_fix(TARGET_REPO, TARGET_BRANCH)

    assert pr_url is not None, (
        "execute_ephemeral_fix returned None — PR was not created.\n"
        "Check stdout above for which step failed:\n"
        "  'No supported build file found'  → requirements.txt not in repo root\n"
        "  'No vulnerabilities found'        → OSV scan did not detect CVEs\n"
        "  'Build still failing'             → LLM patch did not fix pip install\n"
        "  'Push failed'                     → GITHUB_TOKEN lacks fork/push scope"
    )
    print(f"\n  PR created: {pr_url}")
    print(f"\n  Open the PR to verify:")
    print(f"    - requirements.txt bumps all 4 vulnerable packages")
    print(f"    - app/config.py uses yaml.safe_load() at all call sites")
    print(f"    - app/cache.py pickle usage is replaced or guarded")
