"""
Python source-patching e2e: proves Sentinel patches BOTH build files AND
Python source files containing dangerous patterns in a single PR-worthy commit.

This is the Python equivalent of test_java_source_patching_e2e.py, and it is
MORE complex because:
  - 4 CVEs across 3 packages (vs 1 CVE in the Java test)
  - 2 source files with dangerous patterns (config.py + cache.py)
  - Patches span 3 file types: requirements.txt, *.py (unsafe API), *.py (deserialization)
  - Source patching is PROACTIVE (no runtime error required) — a stronger guarantee

Setup:
  requirements.txt: PyYAML 5.3.1 + cryptography 3.3.2 + requests 2.27.0
  app/config.py:   yaml.load() calls (GHSA-8q59-q68h-6hv4 exploit pattern)
  app/cache.py:    pickle.loads() calls (unsafe deserialization, always flagged)

Expected outcome after autonomous_patch:
  - requirements.txt: versions bumped to safe minimums
  - app/config.py: yaml.load() → yaml.safe_load()
  - app/cache.py: pickle.loads() replaced or guarded with a comment
  - pip3 install --user -r requirements.txt && pip3 check: exit 0

Requirements: Docker running, GEMINI_API_KEY.

Run: pytest tests/test_python_source_patching_e2e.py -v -s
"""
import base64
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "orchestrator"))

WORKSPACE = "/home/agent/workspace"

# ── Controlled vulnerable project ─────────────────────────────────────────────

VULNERABLE_REQUIREMENTS = """\
# GHSA-8q59-q68h-6hv4: PyYAML < 6.0 arbitrary code execution
PyYAML==5.3.1
# GHSA-v8gr-m533-ghj9: cryptography < 39.0.1 RSA decryption oracle
cryptography==3.3.2
# GHSA-j8r2-6x86-q33q: requests < 2.31.0 auth headers leaked on redirect
requests==2.27.0
"""

# yaml.load() with no Loader= is the canonical PyYAML exploit pattern.
# Upgrading to PyYAML 6 alone does NOT fix this — source must also change.
CONFIG_PY = """\
\"\"\"
Config loader — reads YAML configuration files from disk and environment.
SECURITY ISSUE: yaml.load() allows arbitrary Python object instantiation.
Attackers who control the YAML file can achieve RCE (GHSA-8q59-q68h-6hv4).
\"\"\"
import yaml
import os


def load_app_config(config_path: str) -> dict:
    \"\"\"Load primary application config from a YAML file.\"\"\"
    with open(config_path, "r") as f:
        return yaml.load(f)          # UNSAFE: no Loader= specified


def load_env_overrides(yaml_string: str) -> dict:
    \"\"\"Parse YAML string from an environment variable override.\"\"\"
    return yaml.load(yaml_string)    # UNSAFE: attacker-controlled input


def merge_configs(*paths: str) -> dict:
    \"\"\"Merge multiple YAML config files, later files take precedence.\"\"\"
    merged = {}
    for path in paths:
        if os.path.exists(path):
            with open(path) as f:
                partial = yaml.load(f)   # UNSAFE
            merged.update(partial or {})
    return merged
"""

# pickle.loads on untrusted data is always dangerous — Sentinel flags it
# regardless of the specific GHSA IDs found, via _PYTHON_ALWAYS_CHECK.
CACHE_PY = """\
\"\"\"
In-memory session cache backed by serialized Python objects.
SECURITY ISSUE: pickle.loads() on data from Redis/memcache allows RCE
if an attacker can write to the cache store.
\"\"\"
import pickle
import hashlib


class SessionCache:
    def __init__(self):
        self._store: dict = {}

    def put(self, key: str, value: object) -> None:
        \"\"\"Serialize and store a session object.\"\"\"
        self._store[key] = pickle.dumps(value)

    def get(self, key: str) -> object:
        \"\"\"Deserialize and return a session object.\"\"\"
        raw = self._store.get(key)
        if raw is None:
            return None
        return pickle.loads(raw)     # UNSAFE: deserializes arbitrary bytes

    def get_from_network(self, raw_bytes: bytes) -> object:
        \"\"\"Deserialize bytes received over the network — most dangerous pattern.\"\"\"
        return pickle.loads(raw_bytes)   # UNSAFE: attacker-controlled bytes
"""


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def require_env():
    missing = [v for v in ("GEMINI_API_KEY",) if not os.getenv(v)]
    if missing:
        pytest.skip(f"Missing env vars: {missing}")
    try:
        import docker
        docker.from_env().ping()
    except Exception as exc:
        pytest.skip(f"Docker unavailable: {exc}")


@pytest.fixture(scope="module")
def docker_client():
    import docker
    return docker.from_env()


@pytest.fixture(scope="module")
def sandbox_container(docker_client):
    c = docker_client.containers.run(
        image="cve-fixer-sandbox:latest",
        command="/bin/bash",
        detach=True,
        tty=True,
        environment={"GEMINI_API_KEY": os.getenv("GEMINI_API_KEY", "")},
    )
    c.exec_run(f"rm -rf {WORKSPACE}", workdir="/")
    c.exec_run(f"mkdir -p {WORKSPACE}/app", workdir="/")

    _write(c, "requirements.txt", VULNERABLE_REQUIREMENTS)
    _write(c, "app/config.py", CONFIG_PY)
    _write(c, "app/cache.py", CACHE_PY)
    _write(c, "app/__init__.py", "")

    c.exec_run("git init", workdir=WORKSPACE)
    c.exec_run("git config user.email 'test@test.com'", workdir=WORKSPACE)
    c.exec_run("git config user.name 'Test'", workdir=WORKSPACE)
    c.exec_run("git add .", workdir=WORKSPACE)
    c.exec_run("git commit -m 'initial vulnerable state'", workdir=WORKSPACE)

    yield c
    c.stop()
    c.remove()


def _write(container, filename: str, content: str):
    encoded = base64.b64encode(content.encode()).decode("ascii")
    python_code = f"import base64; open('{filename}','wb').write(base64.b64decode('{encoded}'))"
    r = container.exec_run(["python3", "-c", python_code], workdir=WORKSPACE)
    assert r.exit_code == 0, f"write {filename} failed: {r.output.decode()}"


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestPythonMultiFilePatch:

    def test_osv_finds_multiple_cves(self, sandbox_container):
        """OSV-Scanner (or API) finds all three vulnerable packages."""
        with patch("factory.docker.from_env"):
            from factory import RemediationFactory
            factory = RemediationFactory()

        cves = factory._scan_internal(sandbox_container, WORKSPACE, "python")
        assert len(cves) >= 2, (
            f"Expected ≥2 CVEs across PyYAML/cryptography/requests, got: {cves}"
        )
        print(f"\n  CVEs found: {cves}")

    def test_dangerous_patterns_present_before_patching(self, sandbox_container):
        """Both dangerous source patterns are present before Sentinel runs."""
        grep_yaml = sandbox_container.exec_run(
            ["grep", "-r", "yaml.load(", "app/"], workdir=WORKSPACE
        )
        assert grep_yaml.exit_code == 0, "yaml.load( not found in source — fixture setup error"

        grep_pickle = sandbox_container.exec_run(
            ["grep", "-r", "pickle.loads(", "app/"], workdir=WORKSPACE
        )
        assert grep_pickle.exit_code == 0, "pickle.loads( not found in source — fixture setup error"
        print("\n  Confirmed: yaml.load() and pickle.loads() present before patching")

    def test_autonomous_patch_fixes_all_three_files(self, sandbox_container):
        """
        autonomous_patch must fix:
          1. requirements.txt — version bumps for PyYAML, cryptography, requests
          2. app/config.py   — yaml.load() → yaml.safe_load()
          3. app/cache.py    — pickle.loads() guarded or replaced

        Python source patching is PROACTIVE: triggered by grep pattern scan,
        not by a runtime error. This fires on the FIRST autonomous_patch call.
        """
        with patch("factory.docker.from_env"):
            from factory import RemediationFactory
            factory = RemediationFactory()
        from remediator import RemediationActor

        cves = factory._scan_internal(sandbox_container, WORKSPACE, "python")
        assert cves, "No CVEs found — cannot run patching test"

        actor = RemediationActor(sandbox_container, MagicMock(), "python", "requirements.txt")
        patched = actor.autonomous_patch(cves)
        assert patched, "autonomous_patch returned False — LLM or write step failed"

        # Verify environment is clean after patching
        verify = sandbox_container.exec_run(
            "pip3 install --user -r requirements.txt -q && pip3 check",
            workdir=WORKSPACE
        )
        assert verify.exit_code == 0, (
            f"pip check failed after patching:\n{verify.output.decode()[-1500:]}"
        )
        print("\n  pip check passed after patching!")

        # All three files must appear in git diff
        diff = sandbox_container.exec_run("git diff --name-only", workdir=WORKSPACE)
        changed = diff.output.decode().splitlines()
        print(f"\n  Files changed by Sentinel: {changed}")

        assert any("requirements.txt" in f for f in changed), (
            f"requirements.txt not patched. Changed: {changed}"
        )
        py_changed = [f for f in changed if f.endswith(".py")]
        assert len(py_changed) >= 2, (
            f"Expected ≥2 Python source files patched (config.py + cache.py), "
            f"got: {py_changed}"
        )
        print(f"\n  Python source files patched: {py_changed}")

    def test_yaml_load_replaced_in_config(self, sandbox_container):
        """After patching, config.py must not call yaml.load() unsafely."""
        cat = sandbox_container.exec_run("cat app/config.py", workdir=WORKSPACE)
        content = cat.output.decode()
        assert "yaml.safe_load" in content, (
            f"yaml.safe_load not found in patched config.py:\n{content}"
        )
        print(f"\n  config.py after patching:\n{content[:600]}")

    def test_pickle_addressed_in_cache(self, sandbox_container):
        """After patching, cache.py must have pickle usage addressed."""
        cat = sandbox_container.exec_run("cat app/cache.py", workdir=WORKSPACE)
        content = cat.output.decode()
        # LLM may add a warning comment, remove the pattern, or replace it —
        # any change that addresses the risk is acceptable
        has_guard = (
            "# SECURITY" in content
            or "# WARNING" in content
            or "# nosec" in content
            or "json" in content
            or "msgpack" in content
            or "pickle.loads" not in content
        )
        assert has_guard, (
            f"pickle.loads() in cache.py was not addressed after patching:\n{content}"
        )
        print(f"\n  cache.py after patching:\n{content[:600]}")
