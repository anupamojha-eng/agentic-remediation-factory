"""
End-to-end tests for Python build system support using a real Docker sandbox.

Proves the full scan → patch → install cycle for requirements.txt and
pyproject.toml without touching GitHub.

Requirements:
  - Docker daemon running
  - ANTHROPIC_API_KEY (Claude, recommended) or GEMINI_API_KEY (Gemini)
  - Sandbox image built: docker build -t cve-fixer-sandbox:latest sandbox/

Run: pytest tests/test_e2e_python_docker.py -v -s
"""
import base64
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "orchestrator"))

FIXTURES = Path(__file__).parent / "fixtures"
WORKSPACE = "/home/agent/workspace"


# ── Docker / image fixtures ────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def docker_client():
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return client
    except Exception as exc:
        pytest.skip(f"Docker daemon unavailable: {exc}")


@pytest.fixture(scope="session")
def sandbox_image(docker_client):
    import docker as docker_module
    sandbox_dir = str(Path(__file__).parent.parent / "sandbox")
    try:
        return docker_client.images.get("cve-fixer-sandbox:latest")
    except docker_module.errors.ImageNotFound:
        print("\nSandbox image not found — building (~5 min first time)...")
        image, logs = docker_client.images.build(
            path=sandbox_dir, tag="cve-fixer-sandbox:latest", rm=True
        )
        for chunk in logs:
            if "stream" in chunk:
                print(chunk["stream"], end="", flush=True)
        return image


@pytest.fixture
def container(docker_client, sandbox_image):
    """Fresh sandbox container per test — Python-only workspace."""
    env = {}
    for key in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_MODEL",
                "GEMINI_MODEL", "LLM_PROVIDER"):
        val = os.getenv(key)
        if val:
            env[key] = val
    c = docker_client.containers.run(
        image="cve-fixer-sandbox:latest",
        command="/bin/bash",
        detach=True,
        tty=True,
        environment=env,
    )
    # Remove sandbox's own requirements.txt to prevent it polluting OSV scans
    c.exec_run("rm -f requirements.txt", workdir=WORKSPACE)
    yield c
    c.stop()
    c.remove()


@pytest.fixture(scope="session")
def require_gemini_key():
    if not os.getenv("ANTHROPIC_API_KEY") and not os.getenv("GEMINI_API_KEY"):
        pytest.skip("Set ANTHROPIC_API_KEY (Claude) or GEMINI_API_KEY (Gemini)")


# ── Helpers ────────────────────────────────────────────────────────────────────

def copy_file(container, workspace, filename, content_bytes):
    encoded = base64.b64encode(content_bytes).decode("ascii")
    parent = os.path.dirname(filename)
    if parent:
        container.exec_run(f"mkdir -p {parent}", workdir=workspace)
    python_code = f"import base64; open('{filename}','wb').write(base64.b64decode('{encoded}'))"
    result = container.exec_run(["python3", "-c", python_code], workdir=workspace)
    if result.exit_code != 0:
        raise RuntimeError(f"Failed to copy {filename}: {result.output.decode()}")


def make_factory():
    with patch("factory.docker.from_env"):
        from factory import RemediationFactory
        f = RemediationFactory()
        f.gh_token = "test-token"
        return f


# ── requirements.txt end-to-end ────────────────────────────────────────────────

class TestPythonRequirementsEndToEnd:
    """Full scan → patch → pip-install cycle with a requirements.txt fixture."""

    @pytest.fixture(autouse=True)
    def _setup(self, require_gemini_key, container):
        copy_file(container, WORKSPACE, "requirements.txt",
                  (FIXTURES / "vulnerable_requirements.txt").read_bytes())
        self.container = container

    def test_detects_python_build_system(self):
        build_system, build_file = make_factory()._detect_build_system(
            self.container, WORKSPACE)
        assert build_system == "python"
        assert build_file == "requirements.txt"

    def test_osv_scan_finds_cves(self):
        cves = make_factory()._scan_internal(self.container, WORKSPACE, "python")
        assert len(cves) > 0, (
            "No CVEs found in vulnerable_requirements.txt — "
            "check that OSV-Scanner supports Python and the package versions are still flagged"
        )
        print(f"\n  CVEs found: {cves}")

    def test_full_scan_patch_verify_cycle(self):
        from remediator import RemediationActor

        factory = make_factory()
        build_system, build_file = factory._detect_build_system(self.container, WORKSPACE)
        cves = factory._scan_internal(self.container, WORKSPACE, build_system)
        assert cves, "No CVEs found — cannot test patching"

        actor = RemediationActor(self.container, MagicMock(), build_system, build_file)
        assert actor.autonomous_patch(cves), "autonomous_patch returned False"

        # Verify: patched requirements.txt must install cleanly
        verify_cmd = factory._get_verify_command(build_system, self.container, WORKSPACE)
        result = self.container.exec_run(verify_cmd, workdir=WORKSPACE)
        assert result.exit_code == 0, (
            f"pip install failed after patching.\nCommand: {verify_cmd}\n"
            f"Output:\n{result.output.decode()}"
        )
        print(f"\n  Verify passed with: {verify_cmd}")

        # Confirm requirements.txt was actually modified
        diff = self.container.exec_run("git diff --name-only", workdir=WORKSPACE)
        changed = diff.output.decode().splitlines()
        assert any("requirements.txt" in f for f in changed), (
            f"requirements.txt was not patched. Changed files: {changed}"
        )
        print(f"\n  Patched files: {changed}")


# ── pyproject.toml end-to-end ─────────────────────────────────────────────────

class TestPythonPyprojectEndToEnd:
    """Detection and scan for pyproject.toml — OSV-Scanner reads it natively."""

    @pytest.fixture(autouse=True)
    def _setup(self, require_gemini_key, container):
        copy_file(container, WORKSPACE, "pyproject.toml",
                  (FIXTURES / "vulnerable_pyproject.toml").read_bytes())
        self.container = container

    def test_detects_pyproject_toml(self):
        build_system, build_file = make_factory()._detect_build_system(
            self.container, WORKSPACE)
        assert build_system == "python"
        assert build_file == "pyproject.toml"

    def test_osv_scan_finds_cves_in_pyproject(self):
        cves = make_factory()._scan_internal(self.container, WORKSPACE, "python")
        assert len(cves) > 0, "No CVEs found in vulnerable_pyproject.toml"
        print(f"\n  CVEs found in pyproject.toml: {cves}")


# ── Source-file patching (proactive grep scan) ────────────────────────────────

class TestPythonSourcePatchingDockerEndToEnd:
    """
    Proves that Sentinel patches BOTH requirements.txt AND Python source files
    in a single autonomous_patch call — without a compile error triggering it.

    The key difference from Java: Python source patching is PROACTIVE — Sentinel
    greps for dangerous patterns (yaml.load, pickle.loads) and patches them
    preventively, even when the build passes.  This is a stronger security
    guarantee than Java's error-driven patching.
    """

    REQUIREMENTS = """\
# GHSA-8q59-q68h-6hv4: PyYAML < 6.0 arbitrary code execution
PyYAML==5.3.1
requests==2.27.0
"""

    CONFIG_PY = """\
\"\"\"Application config loader — loads YAML configuration files.\"\"\"
import yaml


def load_config(path: str) -> dict:
    with open(path) as f:
        # BUG: yaml.load() without Loader= allows arbitrary code execution
        # Attackers can embed !!python/object payloads in YAML files
        return yaml.load(f)


def load_config_string(content: str) -> dict:
    # Same issue — yaml.load on untrusted input
    return yaml.load(content)
"""

    @pytest.fixture(autouse=True)
    def _setup(self, require_gemini_key, docker_client, sandbox_image):
        c = docker_client.containers.run(
            image="cve-fixer-sandbox:latest",
            command="/bin/bash",
            detach=True,
            tty=True,
            environment={"GEMINI_API_KEY": os.getenv("GEMINI_API_KEY", "")},
        )
        c.exec_run("rm -f requirements.txt", workdir=WORKSPACE)
        c.exec_run("mkdir -p app", workdir=WORKSPACE)

        _write(c, "requirements.txt", self.REQUIREMENTS)
        _write(c, "app/config.py", self.CONFIG_PY)

        c.exec_run("git init", workdir=WORKSPACE)
        c.exec_run("git config user.email 'test@test.com'", workdir=WORKSPACE)
        c.exec_run("git config user.name 'Test'", workdir=WORKSPACE)
        c.exec_run("git add .", workdir=WORKSPACE)
        c.exec_run("git commit -m 'initial'", workdir=WORKSPACE)

        self.container = c
        yield
        c.stop()
        c.remove()

    def test_autonomous_patch_fixes_both_requirements_and_source(self):
        """
        autonomous_patch must:
        1. Upgrade PyYAML in requirements.txt (CVE fix)
        2. Replace yaml.load() with yaml.safe_load() in app/config.py (source fix)

        The source fix happens PROACTIVELY via grep — not triggered by a runtime error.
        """
        from factory import RemediationFactory
        from remediator import RemediationActor

        with patch("factory.docker.from_env"):
            factory = RemediationFactory()

        cves = factory._scan_internal(self.container, WORKSPACE, "python")
        assert cves, "OSV found no CVEs — cannot test patching"
        print(f"\n  CVEs to fix: {cves}")

        actor = RemediationActor(self.container, MagicMock(), "python", "requirements.txt")
        patched = actor.autonomous_patch(cves)
        assert patched, "autonomous_patch returned False"

        # Verify install passes with patched requirements
        result = self.container.exec_run(
            "pip3 install --user -r requirements.txt -q && pip3 check",
            workdir=WORKSPACE
        )
        assert result.exit_code == 0, (
            f"pip install failed after patching:\n{result.output.decode()}"
        )
        print("\n  pip install passed after patching!")

        # Both files must have changed
        diff = self.container.exec_run("git diff --name-only", workdir=WORKSPACE)
        changed = diff.output.decode().splitlines()
        print(f"\n  Files changed: {changed}")

        assert any("requirements.txt" in f for f in changed), (
            f"requirements.txt not patched. Changed: {changed}"
        )
        assert any(".py" in f for f in changed), (
            f"No Python source files were patched — proactive source scan didn't trigger.\n"
            f"Changed: {changed}"
        )
        print("\n  Both requirements.txt and Python source files patched!")

        # Confirm yaml.load was replaced in the patched source
        cat = self.container.exec_run("cat app/config.py", workdir=WORKSPACE)
        patched_src = cat.output.decode()
        assert "yaml.safe_load" in patched_src, (
            f"yaml.load() was not replaced with yaml.safe_load() in app/config.py.\n"
            f"Patched content:\n{patched_src}"
        )
        assert "yaml.load(" not in patched_src or "yaml.safe_load(" in patched_src, (
            "Unsafe yaml.load() still present after patching"
        )
        print("\n  yaml.load() → yaml.safe_load() replacement confirmed!")


def _write(container, filename: str, content: str):
    encoded = base64.b64encode(content.encode()).decode("ascii")
    python_code = f"import base64; open('{filename}','wb').write(base64.b64decode('{encoded}'))"
    r = container.exec_run(["python3", "-c", python_code], workdir=WORKSPACE)
    assert r.exit_code == 0, f"write {filename} failed: {r.output.decode()}"
