"""Unit tests for build system detection and verify command selection. No external deps."""
import sys
import os
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'orchestrator'))


def exec_result(exit_code, output=b""):
    r = MagicMock()
    r.exit_code = exit_code
    r.output = output
    return r


@pytest.fixture
def factory():
    with patch('factory.docker.from_env'):
        from factory import RemediationFactory
        f = RemediationFactory()
        f.gh_token = "fake"
        return f


@pytest.fixture
def container():
    return MagicMock()


class TestDetectBuildSystem:
    def test_detects_maven(self, factory, container):
        container.exec_run.side_effect = [exec_result(0)]
        assert factory._detect_build_system(container, "/ws") == ("maven", "pom.xml")

    def test_detects_gradle_kts_when_no_pom(self, factory, container):
        container.exec_run.side_effect = [
            exec_result(1),  # no pom.xml
            exec_result(0),  # build.gradle.kts found
        ]
        assert factory._detect_build_system(container, "/ws") == ("gradle", "build.gradle.kts")

    def test_detects_gradle_groovy_when_no_pom_or_kts(self, factory, container):
        container.exec_run.side_effect = [
            exec_result(1),  # no pom.xml
            exec_result(1),  # no build.gradle.kts
            exec_result(0),  # build.gradle found
        ]
        assert factory._detect_build_system(container, "/ws") == ("gradle", "build.gradle")

    def test_returns_none_when_no_build_file(self, factory, container):
        container.exec_run.return_value = exec_result(1)
        assert factory._detect_build_system(container, "/ws") == (None, None)

    def test_maven_takes_priority_over_gradle(self, factory, container):
        container.exec_run.side_effect = [exec_result(0)]  # pom.xml found immediately
        build_system, _ = factory._detect_build_system(container, "/ws")
        assert build_system == "maven"
        assert container.exec_run.call_count == 1  # stopped after finding pom.xml

    def test_kts_takes_priority_over_groovy(self, factory, container):
        container.exec_run.side_effect = [
            exec_result(1),  # no pom.xml
            exec_result(0),  # build.gradle.kts found
        ]
        _, build_file = factory._detect_build_system(container, "/ws")
        assert build_file == "build.gradle.kts"
        assert container.exec_run.call_count == 2  # stopped after finding kts


class TestGetVerifyCommand:
    def test_maven_returns_mvn(self, factory, container):
        assert factory._get_verify_command("maven", container, "/ws") == "mvn clean compile"

    def test_gradle_prefers_wrapper_script(self, factory, container):
        container.exec_run.return_value = exec_result(0)  # gradlew exists
        assert factory._get_verify_command("gradle", container, "/ws") == "./gradlew compileJava"

    def test_gradle_falls_back_to_system_gradle(self, factory, container):
        container.exec_run.return_value = exec_result(1)  # no gradlew
        assert factory._get_verify_command("gradle", container, "/ws") == "gradle compileJava"
