"""
End-to-end tests using a real Docker sandbox container.

These tests prove the full scan → patch → compile cycle works for both
Maven and Gradle projects without touching GitHub.

Requirements:
  - Docker daemon running
  - GEMINI_API_KEY set
  - Sandbox image built (auto-built if absent, takes ~5 min first time)

Run: pytest tests/test_e2e_docker.py -v -s
"""
import io
import os
import sys
import tarfile
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
        print("\nSandbox image not found — building (this takes ~5 minutes the first time)...")
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
    c.exec_run(f"mkdir -p {WORKSPACE}")
    yield c
    c.stop()
    c.remove()


@pytest.fixture(scope="session")
def require_gemini_key():
    if not os.getenv("GEMINI_API_KEY"):
        pytest.skip("GEMINI_API_KEY not set")


# ── Helpers ────────────────────────────────────────────────────────────────────

def copy_file_to_container(container, workspace, filename, content_bytes):
    """Transfer a single file into a running container via put_archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=filename)
        info.size = len(content_bytes)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content_bytes))
    buf.seek(0)
    container.put_archive(workspace, buf)


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
        copy_file_to_container(
            container, WORKSPACE, "pom.xml",
            (FIXTURES / "vulnerable_pom.xml").read_bytes()
        )
        self.container = container

    def test_detects_maven_build_system(self):
        factory = make_factory()
        build_system, build_file = factory._detect_build_system(self.container, WORKSPACE)
        assert build_system == "maven"
        assert build_file == "pom.xml"

    def test_osv_scanner_finds_cves(self):
        factory = make_factory()
        cves = factory._scan_internal(self.container, WORKSPACE)
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


# ── Gradle end-to-end ──────────────────────────────────────────────────────────

class TestGradleEndToEnd:
    @pytest.fixture(autouse=True)
    def _setup(self, require_gemini_key, container):
        copy_file_to_container(
            container, WORKSPACE, "build.gradle",
            (FIXTURES / "vulnerable_build.gradle").read_bytes()
        )
        self.container = container

    def test_detects_gradle_build_system(self):
        factory = make_factory()
        build_system, build_file = factory._detect_build_system(self.container, WORKSPACE)
        assert build_system == "gradle"
        assert build_file == "build.gradle"

    def test_osv_scanner_finds_cves(self):
        factory = make_factory()
        cves = factory._scan_internal(self.container, WORKSPACE)
        assert len(cves) > 0, "OSV-Scanner found no CVEs in vulnerable build.gradle"
        print(f"\n  CVEs found: {cves}")

    def test_full_scan_patch_compile_cycle(self):
        from remediator import RemediationActor

        factory = make_factory()
        build_system, build_file = factory._detect_build_system(self.container, WORKSPACE)
        cves = factory._scan_internal(self.container, WORKSPACE)
        assert cves, "No CVEs found — cannot test patching"

        actor = RemediationActor(self.container, MagicMock(), build_system, build_file)
        assert actor.autonomous_patch(cves), "autonomous_patch returned False"

        # Use system gradle (no wrapper in the fixture project)
        result = self.container.exec_run("gradle compileJava", workdir=WORKSPACE)
        assert result.exit_code == 0, (
            f"Build failed after patching.\n"
            f"Output:\n{result.output.decode()}"
        )
        print("\n  Build passed with: gradle compileJava")


# ── Gradle Kotlin DSL end-to-end ───────────────────────────────────────────────

class TestGradleKtsEndToEnd:
    @pytest.fixture(autouse=True)
    def _setup(self, require_gemini_key, container):
        copy_file_to_container(
            container, WORKSPACE, "build.gradle.kts",
            (FIXTURES / "vulnerable_build.gradle.kts").read_bytes()
        )
        self.container = container

    def test_detects_gradle_kts_build_system(self):
        factory = make_factory()
        build_system, build_file = factory._detect_build_system(self.container, WORKSPACE)
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

        result = self.container.exec_run("gradle compileJava", workdir=WORKSPACE)
        assert result.exit_code == 0, (
            f"Build failed after patching.\n"
            f"Output:\n{result.output.decode()}"
        )
        print("\n  Build passed with: gradle compileJava")
