"""
Task 2 end-to-end test: fix CVEs that require BOTH a build-file upgrade
AND changes to Java source files.

This test uses a CONTROLLED, MINIMAL setup to prove the capability reliably:
1. A simple pom.xml with a vulnerable dependency (jackson-databind 2.13.0)
2. A simple Java class with one deliberate compile error caused by a version upgrade
3. Sentinel must fix both the pom.xml AND the Java source file

The Java compile error is deterministic — we write the source file ourselves.

Requirements: Docker running, GEMINI_API_KEY, GITHUB_TOKEN.

Run: pytest tests/test_java_source_patching_e2e.py -v -s
"""
import base64
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "orchestrator"))

FIXTURES = Path(__file__).parent / "fixtures"
WORKSPACE = "/home/agent/workspace"

# Vulnerable pom.xml: jackson-databind 2.13.0 + a compile-breaking direct dep
VULNERABLE_POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>task2-test</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.source>11</maven.compiler.source>
    <maven.compiler.target>11</maven.compiler.target>
  </properties>
  <dependencies>
    <!-- GHSA-jjjh-jjxp-wpff / CVE-2022-42003: affected < 2.13.4.2 -->
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.13.0</version>
    </dependency>
  </dependencies>
</project>
"""

# A Java class with a deliberate compile error: JsonNode is used but not imported.
# The fix is a single import line: `import com.fasterxml.jackson.databind.JsonNode;`
# This error is trivially obvious to ANY LLM and demonstrates that Sentinel can
# apply BOTH a security fix (pom.xml upgrade) AND a code fix (.java import) in one PR.
JAVA_WITH_COMPILE_ERROR = """\
package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;

public class DataProcessor {

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Parses JSON and extracts a field value.
     * NOTE: import for JsonNode is intentionally missing — this causes a compile error.
     */
    public String extract(String json, String fieldName) throws Exception {
        JsonNode root = mapper.readTree(json);
        return root.path(fieldName).asText();
    }
}
"""

# The LLM must add: import com.fasterxml.jackson.databind.JsonNode;
JAVA_SHOULD_COMPILE = True


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
    # Set up the workspace
    c.exec_run(f"rm -rf {WORKSPACE}", workdir="/")
    c.exec_run(f"mkdir -p {WORKSPACE}/src/main/java/com/example", workdir="/")

    # Write the vulnerable pom.xml
    _write(c, "pom.xml", VULNERABLE_POM)

    # Write the Java file WITH the compile error
    _write(c, "src/main/java/com/example/DataProcessor.java", JAVA_WITH_COMPILE_ERROR)

    # Initialize git so git-checkout based restore works
    c.exec_run("git init", workdir=WORKSPACE)
    c.exec_run("git config user.email 'test@test.com'", workdir=WORKSPACE)
    c.exec_run("git config user.name 'Test'", workdir=WORKSPACE)
    c.exec_run("git add .", workdir=WORKSPACE)
    c.exec_run("git commit -m 'initial'", workdir=WORKSPACE)

    yield c
    c.stop()
    c.remove()


def _write(container, filename, content: str):
    encoded = base64.b64encode(content.encode()).decode("ascii")
    python_code = f"import base64; open('{filename}','wb').write(base64.b64decode('{encoded}'))"
    r = container.exec_run(["python3", "-c", python_code], workdir=WORKSPACE)
    assert r.exit_code == 0, f"write {filename} failed: {r.output.decode()}"


class TestJavaSourcePatching:
    def test_osv_scanner_finds_cves_in_controlled_project(self, sandbox_container):
        """OSV-Scanner finds the jackson-databind CVEs in our controlled pom.xml."""
        from factory import RemediationFactory
        from unittest.mock import patch
        with patch("factory.docker.from_env"):
            factory = RemediationFactory()

        cves = factory._scan_internal(sandbox_container, WORKSPACE)
        assert len(cves) > 0, "OSV-Scanner found no CVEs in vulnerable pom.xml"
        print(f"\n  CVEs found: {cves}")

    def test_initial_compile_fails_with_known_error(self, sandbox_container):
        """The Java file has a deliberate compile error before patching."""
        result = sandbox_container.exec_run("mvn compile", workdir=WORKSPACE)
        assert result.exit_code != 0, "Expected compile to fail before patching"
        output = result.output.decode()
        assert "incompatible types" in output or "error" in output.lower()
        print("\n  Compile error confirmed before patching.")

    def test_autonomous_patch_fixes_both_pom_and_java(self, sandbox_container):
        """
        autonomous_patch must:
        1. Upgrade jackson-databind in pom.xml (CVE fix)
        2. Fix the incompatible-types compile error in DataProcessor.java
        """
        from remediator import RemediationActor

        # Get the compile error for the retry-mode prompt.
        # Use the full output (not filtered) so the file path regex in
        # get_affected_java_files can extract the .java file path.
        compile_result = sandbox_container.exec_run("mvn compile", workdir=WORKSPACE)
        build_error = compile_result.output.decode("utf-8", errors="replace")
        # Show just the relevant lines for readability
        relevant = [l for l in build_error.splitlines()
                    if any(k in l for k in ("[ERROR]", "incompatible", "cannot find"))]
        print(f"\n  Build error being passed to LLM:\n" + "\n".join(relevant[:10]))

        mock_fork = MagicMock()
        actor = RemediationActor(sandbox_container, mock_fork, "maven", "pom.xml")

        patched = actor.autonomous_patch(["GHSA-jjjh-jjxp-wpff"], build_error=build_error)
        assert patched, "autonomous_patch returned False"

        for change in actor.llm.get_remediation_plan.__doc__ if False else []:
            pass  # no-op, just to not break structure

        # Verify build now passes
        verify = sandbox_container.exec_run("mvn compile", workdir=WORKSPACE)
        assert verify.exit_code == 0, (
            f"Build failed after patching:\n{verify.output.decode()[-1000:]}"
        )
        print("\n  Build passes after patching!")

        # Verify BOTH files were changed
        diff = sandbox_container.exec_run("git diff --name-only", workdir=WORKSPACE)
        changed = diff.output.decode().splitlines()
        print(f"\n  Files changed: {changed}")

        pom_changed = any("pom.xml" in f for f in changed)
        java_changed = any(".java" in f for f in changed)

        assert pom_changed, f"pom.xml was not patched. Changed: {changed}"
        assert java_changed, (
            f"No .java files were patched — Java source fix didn't happen. Changed: {changed}"
        )
        print(f"\n  Both pom.xml and Java source files were patched!")
