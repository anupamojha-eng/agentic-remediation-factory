"""
Integration tests — call the real Gemini API with fixture build files.
Requires GEMINI_API_KEY in environment.

Run: pytest tests/test_llm_integration.py -v -s
"""
import sys
import os
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'orchestrator'))

FIXTURES = Path(__file__).parent / "fixtures"
# GHSA-jjjh-jjxp-wpff = CVE-2022-42003, jackson-databind < 2.13.4.2
GHSA = ["GHSA-jjjh-jjxp-wpff"]
VULNERABLE_VERSION = "2.13.0"


@pytest.fixture(autouse=True, scope="module")
def require_gemini_key():
    if not os.getenv("GEMINI_API_KEY"):
        pytest.skip("GEMINI_API_KEY not set")


@pytest.fixture(scope="module")
def llm_client():
    from llm_client import SecurityAgentClient
    return SecurityAgentClient()


def assert_version_fixed(patched_content, label):
    """The vulnerable version must not appear in patched output."""
    assert VULNERABLE_VERSION not in patched_content, (
        f"{label}: vulnerable version {VULNERABLE_VERSION} still present.\n"
        f"Patched content:\n{patched_content}"
    )


class TestMavenPatch:
    def test_patches_dependency_version_in_pom(self, llm_client):
        pom = (FIXTURES / "vulnerable_pom.xml").read_text()
        result = llm_client.get_remediation_plan(GHSA, {"pom.xml": pom}, "maven")

        assert result is not None, "LLM returned None"
        assert "patches" in result, f"No 'patches' key in: {result}"
        assert "pom.xml" in result["patches"], f"pom.xml not in patches: {result['patches'].keys()}"

        patched = result["patches"]["pom.xml"]
        assert_version_fixed(patched, "Maven pom.xml")
        assert "<dependency>" in patched, "pom.xml structure lost"
        print(f"\nChanges: {result.get('changes')}")


class TestGradleGroovyPatch:
    def test_patches_direct_version_string(self, llm_client):
        gradle = (FIXTURES / "vulnerable_build.gradle").read_text()
        result = llm_client.get_remediation_plan(GHSA, {"build.gradle": gradle}, "gradle")

        assert result is not None
        assert "build.gradle" in result.get("patches", {})
        patched = result["patches"]["build.gradle"]
        assert_version_fixed(patched, "Gradle Groovy direct version")
        print(f"\nChanges: {result.get('changes')}")

    def test_patches_version_variable(self, llm_client):
        gradle = (FIXTURES / "vulnerable_build_with_var.gradle").read_text()
        result = llm_client.get_remediation_plan(GHSA, {"build.gradle": gradle}, "gradle")

        assert result is not None
        assert "build.gradle" in result.get("patches", {})
        patched = result["patches"]["build.gradle"]
        assert_version_fixed(patched, "Gradle version variable")
        print(f"\nChanges: {result.get('changes')}")


class TestGradleKotlinDSLPatch:
    def test_patches_kotlin_dsl_dependency(self, llm_client):
        kts = (FIXTURES / "vulnerable_build.gradle.kts").read_text()
        result = llm_client.get_remediation_plan(GHSA, {"build.gradle.kts": kts}, "gradle")

        assert result is not None
        assert "build.gradle.kts" in result.get("patches", {})
        patched = result["patches"]["build.gradle.kts"]
        assert_version_fixed(patched, "Gradle Kotlin DSL")
        print(f"\nChanges: {result.get('changes')}")


class TestGradleVersionCatalogPatch:
    def test_patches_libs_versions_toml(self, llm_client):
        build_gradle = (FIXTURES / "vulnerable_build_with_catalog.gradle").read_text()
        libs_toml = (FIXTURES / "libs.versions.toml").read_text()

        result = llm_client.get_remediation_plan(
            GHSA,
            {"build.gradle": build_gradle, "gradle/libs.versions.toml": libs_toml},
            "gradle"
        )

        assert result is not None
        patches = result.get("patches", {})
        assert "gradle/libs.versions.toml" in patches, (
            f"Expected libs.versions.toml to be patched. Got: {list(patches.keys())}"
        )
        patched_toml = patches["gradle/libs.versions.toml"]
        assert_version_fixed(patched_toml, "Version catalog (libs.versions.toml)")
        print(f"\nChanges: {result.get('changes')}")
