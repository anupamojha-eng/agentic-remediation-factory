"""Unit tests for RemediationActor patching logic. No external deps."""
import sys
import os
import base64
import pytest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'orchestrator'))


def exec_result(exit_code, output=b""):
    r = MagicMock()
    r.exit_code = exit_code
    r.output = output
    return r


def make_actor(build_system="maven", build_file="pom.xml"):
    with patch('remediator.SecurityAgentClient'):
        from remediator import RemediationActor
        container = MagicMock()
        container.exec_run.return_value = exec_result(0)
        actor = RemediationActor(container, MagicMock(), build_system, build_file)
        return actor, container


class TestWriteFile:
    def test_writes_content_via_base64(self):
        actor, container = make_actor()
        content = "<project>patched</project>"
        actor._write_file("pom.xml", content)

        # Should call exec_run with ["python3", "-c", <base64 decode script>]
        write_call = next(
            c for c in container.exec_run.call_args_list
            if isinstance(c.args[0], list) and c.args[0][0] == "python3"
        )
        cmd = write_call.args[0]
        assert cmd[1] == "-c"
        encoded = base64.b64encode(content.encode()).decode("ascii")
        assert encoded in cmd[2]

    def test_creates_parent_dir_for_nested_path(self):
        actor, container = make_actor("gradle", "build.gradle")
        actor._write_file("gradle/libs.versions.toml", "[versions]")

        mkdir_call = next(
            c for c in container.exec_run.call_args_list
            if "mkdir" in str(c)
        )
        assert "gradle" in str(mkdir_call)

    def test_no_mkdir_for_top_level_file(self):
        actor, container = make_actor()
        actor._write_file("pom.xml", "content")

        mkdir_calls = [c for c in container.exec_run.call_args_list if "mkdir" in str(c)]
        assert len(mkdir_calls) == 0

    def test_returns_false_on_exec_failure(self):
        actor, container = make_actor()
        container.exec_run.return_value = exec_result(1, b"error")
        result = actor._write_file("pom.xml", "content")
        assert result is False

    def test_returns_true_on_success(self):
        actor, container = make_actor()
        container.exec_run.return_value = exec_result(0)
        result = actor._write_file("pom.xml", "content")
        assert result is True


class TestGetBuildFilesContent:
    def test_maven_returns_only_pom(self):
        actor, container = make_actor("maven", "pom.xml")
        container.exec_run.return_value = exec_result(0, b"<project/>")

        files = actor.get_build_files_content()

        assert list(files.keys()) == ["pom.xml"]
        assert files["pom.xml"] == "<project/>"

    def test_gradle_includes_version_catalog_when_present(self):
        actor, container = make_actor("gradle", "build.gradle")

        def side_effect(cmd, **kwargs):
            if "build.gradle" in str(cmd) and "cat" in str(cmd):
                return exec_result(0, b"dependencies {}")
            if "libs.versions.toml" in str(cmd):
                return exec_result(0, b"[versions]\njackson = \"2.13.0\"")
            return exec_result(1)

        container.exec_run.side_effect = side_effect
        files = actor.get_build_files_content()

        assert "build.gradle" in files
        assert "gradle/libs.versions.toml" in files

    def test_gradle_omits_catalog_when_absent(self):
        actor, container = make_actor("gradle", "build.gradle")

        def side_effect(cmd, **kwargs):
            if "libs.versions.toml" in str(cmd):
                return exec_result(1)  # not present
            return exec_result(0, b"dependencies {}")

        container.exec_run.side_effect = side_effect
        files = actor.get_build_files_content()

        assert "gradle/libs.versions.toml" not in files


class TestAutonomousPatch:
    def test_applies_single_patch_successfully(self):
        with patch('remediator.SecurityAgentClient') as MockLLM:
            MockLLM.return_value.get_remediation_plan.return_value = {
                "patches": {"pom.xml": "<project>patched</project>"},
                "changes": ["Updated jackson-databind to 2.15.0"],
                "analysis": "Fixed CVE"
            }
            from remediator import RemediationActor
            container = MagicMock()
            container.exec_run.return_value = exec_result(0, b"<project>original</project>")
            actor = RemediationActor(container, MagicMock(), "maven", "pom.xml")

            assert actor.autonomous_patch(["GHSA-test"]) is True

    def test_applies_multiple_patches_for_gradle_catalog(self):
        with patch('remediator.SecurityAgentClient') as MockLLM:
            MockLLM.return_value.get_remediation_plan.return_value = {
                "patches": {
                    "build.gradle": "dependencies {}",
                    "gradle/libs.versions.toml": "[versions]\njackson = \"2.15.0\""
                },
                "changes": ["Updated jackson version in catalog"],
                "analysis": "Fixed via catalog"
            }
            from remediator import RemediationActor
            container = MagicMock()
            container.exec_run.return_value = exec_result(0, b"original")
            actor = RemediationActor(container, MagicMock(), "gradle", "build.gradle")

            assert actor.autonomous_patch(["GHSA-test"]) is True

    def test_passes_both_files_to_llm_when_catalog_present(self):
        with patch('remediator.SecurityAgentClient') as MockLLM:
            MockLLM.return_value.get_remediation_plan.return_value = {
                "patches": {"build.gradle": "content"},
                "changes": [],
                "analysis": ""
            }
            from remediator import RemediationActor
            container = MagicMock()

            def side_effect(cmd, **kwargs):
                if "libs.versions.toml" in str(cmd):
                    return exec_result(0, b"[versions]\njackson = \"2.13.0\"")
                return exec_result(0, b"dependencies {}")

            container.exec_run.side_effect = side_effect
            actor = RemediationActor(container, MagicMock(), "gradle", "build.gradle")
            actor.autonomous_patch(["GHSA-test"])

            call_args = MockLLM.return_value.get_remediation_plan.call_args
            files_passed = call_args[0][1]
            assert "build.gradle" in files_passed
            assert "gradle/libs.versions.toml" in files_passed

    def test_returns_false_when_llm_fails(self):
        with patch('remediator.SecurityAgentClient') as MockLLM:
            MockLLM.return_value.get_remediation_plan.return_value = None
            from remediator import RemediationActor
            container = MagicMock()
            container.exec_run.return_value = exec_result(0, b"content")
            actor = RemediationActor(container, MagicMock(), "maven", "pom.xml")

            assert actor.autonomous_patch(["GHSA-test"]) is False

    def test_returns_false_when_llm_returns_empty_patches(self):
        with patch('remediator.SecurityAgentClient') as MockLLM:
            MockLLM.return_value.get_remediation_plan.return_value = {
                "patches": {},
                "changes": [],
                "analysis": "nothing to do"
            }
            from remediator import RemediationActor
            container = MagicMock()
            container.exec_run.return_value = exec_result(0, b"content")
            actor = RemediationActor(container, MagicMock(), "maven", "pom.xml")

            assert actor.autonomous_patch(["GHSA-test"]) is False
