"""
End-to-end tests using a real Docker sandbox container.

Proves the full scan → patch → compile cycle for Maven, Gradle Groovy,
and Gradle Kotlin DSL without touching GitHub.

Requirements:
  - Docker daemon running
  - GEMINI_API_KEY set
  - Sandbox image built (auto-built if absent, ~5 min first time)

Run: pytest tests/test_e2e_docker.py -v -s
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
    """Fresh sandbox container for each test."""
    c = docker_client.containers.run(
        image="cve-fixer-sandbox:latest",
        command="/bin/bash",
        detach=True,
        tty=True,
        environment={"GEMINI_API_KEY": os.getenv("GEMINI_API_KEY", "")},
    )
    # Remove the sandbox's own requirements.txt so it doesn't pollute OSV scans
    c.exec_run("rm -f requirements.txt", workdir=WORKSPACE)
    yield c
    c.stop()
    c.remove()


@pytest.fixture(scope="session")
def require_gemini_key():
    if not os.getenv("GEMINI_API_KEY"):
        pytest.skip("GEMINI_API_KEY not set")


# ── Helpers ────────────────────────────────────────────────────────────────────

def copy_file(container, workspace, filename, content_bytes):
    """Write a file into the container as the agent user via base64, avoiding
    ownership issues that arise when put_archive creates root-owned files."""
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


# ── Maven end-to-end ───────────────────────────────────────────────────────────

class TestMavenEndToEnd:
    @pytest.fixture(autouse=True)
    def _setup(self, require_gemini_key, container):
        # pom.xml is natively understood by OSV-Scanner — no lock file needed
        copy_file(container, WORKSPACE, "pom.xml",
                  (FIXTURES / "vulnerable_pom.xml").read_bytes())
        self.container = container

    def test_detects_maven_build_system(self):
        build_system, build_file = make_factory()._detect_build_system(
            self.container, WORKSPACE)
        assert build_system == "maven"
        assert build_file == "pom.xml"

    def test_osv_scanner_finds_cves(self):
        cves = make_factory()._scan_internal(self.container, WORKSPACE)
        assert len(cves) > 0, "OSV-Scanner found no CVEs in vulnerable pom.xml"
        print(f"\n  CVEs found: {cves}")

    def test_full_scan_patch_compile_cycle(self):
        from remediator import RemediationActor

        factory = make_factory()
        build_system, build_file = factory._detect_build_system(self.container, WORKSPACE)
        cves = factory._scan_internal(self.container, WORKSPACE)
        assert cves, "No CVEs found — cannot test patching"

        actor = RemediationActor(self.container, MagicMock(), build_system, build_file)
        assert actor.autonomous_patch(cves), "autonomous_patch returned False"

        verify_cmd = factory._get_verify_command(build_system, self.container, WORKSPACE)
        result = self.container.exec_run(verify_cmd, workdir=WORKSPACE)
        assert result.exit_code == 0, (
            f"Build failed after patching.\nCommand: {verify_cmd}\n"
            f"Output:\n{result.output.decode()}"
        )
        print(f"\n  Build passed with: {verify_cmd}")


# ── Gradle Groovy end-to-end ───────────────────────────────────────────────────

class TestGradleEndToEnd:
    @pytest.fixture(autouse=True)
    def _setup(self, require_gemini_key, container):
        # OSV-Scanner needs a gradle.lockfile — it does not read build.gradle directly.
        # The lockfile is ignored by Gradle itself (no dependencyLocking block in fixture),
        # so compilation after patching works cleanly with the updated build.gradle.
        copy_file(container, WORKSPACE, "build.gradle",
                  (FIXTURES / "vulnerable_build.gradle").read_bytes())
        copy_file(container, WORKSPACE, "gradle.lockfile",
                  (FIXTURES / "gradle.lockfile").read_bytes())
        self.container = container

    def test_detects_gradle_build_system(self):
        build_system, build_file = make_factory()._detect_build_system(
            self.container, WORKSPACE)
        assert build_system == "gradle"
        assert build_file == "build.gradle"

    def test_osv_scanner_finds_cves(self):
        cves = make_factory()._scan_internal(self.container, WORKSPACE)
        assert len(cves) > 0, "OSV-Scanner found no CVEs in gradle.lockfile"
        print(f"\n  CVEs found: {cves}")

    def test_full_scan_patch_compile_cycle(self):
        from remediator import RemediationActor

        factory = make_factory()
        build_system, build_file = factory._detect_build_system(self.container, WORKSPACE)
        cves = factory._scan_internal(self.container, WORKSPACE)
        assert cves, "No CVEs found — cannot test patching"

        actor = RemediationActor(self.container, MagicMock(), build_system, build_file)
        assert actor.autonomous_patch(cves), "autonomous_patch returned False"

        # gradle.lockfile is stale after patching; remove it so Gradle resolves freely
        self.container.exec_run("rm -f gradle.lockfile", workdir=WORKSPACE)

        result = self.container.exec_run("gradle compileJava", workdir=WORKSPACE)
        assert result.exit_code == 0, (
            f"Build failed after patching.\nOutput:\n{result.output.decode()}"
        )
        print("\n  Build passed with: gradle compileJava")


# ── Gradle Kotlin DSL end-to-end ───────────────────────────────────────────────

class TestGradleKtsEndToEnd:
    @pytest.fixture(autouse=True)
    def _setup(self, require_gemini_key, container):
        copy_file(container, WORKSPACE, "build.gradle.kts",
                  (FIXTURES / "vulnerable_build.gradle.kts").read_bytes())
        copy_file(container, WORKSPACE, "gradle.lockfile",
                  (FIXTURES / "gradle.lockfile").read_bytes())
        self.container = container

    def test_detects_gradle_kts_build_system(self):
        build_system, build_file = make_factory()._detect_build_system(
            self.container, WORKSPACE)
        assert build_system == "gradle"
        assert build_file == "build.gradle.kts"

    def test_full_scan_patch_compile_cycle(self):
        from remediator import RemediationActor

        factory = make_factory()
        build_system, build_file = factory._detect_build_system(self.container, WORKSPACE)
        cves = factory._scan_internal(self.container, WORKSPACE)
        assert cves, "No CVEs found — cannot test patching"

        actor = RemediationActor(self.container, MagicMock(), build_system, build_file)
        assert actor.autonomous_patch(cves), "autonomous_patch returned False"

        self.container.exec_run("rm -f gradle.lockfile", workdir=WORKSPACE)

        result = self.container.exec_run("gradle compileJava", workdir=WORKSPACE)
        assert result.exit_code == 0, (
            f"Build failed after patching.\nOutput:\n{result.output.decode()}"
        )
        print("\n  Build passed with: gradle compileJava")
