"""Unit tests for Python build system support. No external deps."""
import sys
import os
import json
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'orchestrator'))


def exec_result(exit_code, output=b""):
    r = MagicMock()
    r.exit_code = exit_code
    r.output = output.encode() if isinstance(output, str) else output
    return r


def exec_result_demux(exit_code, stdout="", stderr=""):
    r = MagicMock()
    r.exit_code = exit_code
    r.output = (
        stdout.encode() if isinstance(stdout, str) else stdout,
        stderr.encode() if isinstance(stderr, str) else stderr,
    )
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


# ── Build system detection ────────────────────────────────────────────────────

class TestPythonDetection:
    def test_detects_requirements_txt(self, factory, container):
        container.exec_run.side_effect = [
            exec_result(1),  # no pom.xml
            exec_result(1),  # no build.gradle.kts
            exec_result(1),  # no build.gradle
            exec_result(0),  # requirements.txt found
        ]
        assert factory._detect_build_system(container, "/ws") == ("python", "requirements.txt")

    def test_detects_pipfile(self, factory, container):
        container.exec_run.side_effect = [
            exec_result(1), exec_result(1), exec_result(1),  # no JVM
            exec_result(1),  # no requirements.txt
            exec_result(0),  # Pipfile found
        ]
        assert factory._detect_build_system(container, "/ws") == ("python", "Pipfile")

    def test_detects_pyproject_toml(self, factory, container):
        container.exec_run.side_effect = [
            exec_result(1), exec_result(1), exec_result(1),  # no JVM
            exec_result(1), exec_result(1),  # no requirements.txt, no Pipfile
            exec_result(0),  # pyproject.toml found
        ]
        assert factory._detect_build_system(container, "/ws") == ("python", "pyproject.toml")

    def test_jvm_takes_priority_over_python(self, factory, container):
        # pom.xml found first — Python never checked
        container.exec_run.side_effect = [exec_result(0)]
        build_system, _ = factory._detect_build_system(container, "/ws")
        assert build_system == "maven"
        assert container.exec_run.call_count == 1


# ── Verify command ────────────────────────────────────────────────────────────

class TestPythonVerifyCommand:
    def test_python_requirements_txt_without_tests(self, factory, container):
        container.exec_run.return_value = exec_result(1)  # no test dir
        cmd = factory._get_verify_command("python", container, "/ws")
        assert "pip3 install" in cmd
        assert "requirements.txt" in cmd

    def test_python_requirements_txt_with_tests(self, factory, container):
        container.exec_run.return_value = exec_result(0)  # test dir exists
        cmd = factory._get_verify_command("python", container, "/ws")
        assert "pytest" in cmd


# ── Dep list parsing ──────────────────────────────────────────────────────────

class TestParsePythonPipList:
    def test_parses_standard_pip_list_json(self, factory):
        output = json.dumps([
            {"name": "PyYAML", "version": "5.3.1"},
            {"name": "requests", "version": "2.25.0"},
            {"name": "Flask", "version": "1.1.4"},
        ])
        deps = factory._parse_python_pip_list(output)
        assert ("PyYAML", "5.3.1") in deps
        assert ("requests", "2.25.0") in deps
        assert ("Flask", "1.1.4") in deps

    def test_returns_empty_on_invalid_json(self, factory):
        assert factory._parse_python_pip_list("not json") == []

    def test_returns_empty_on_empty_output(self, factory):
        assert factory._parse_python_pip_list("") == []


# ── OSV API ecosystem ─────────────────────────────────────────────────────────

class TestPythonEcosystem:
    def test_query_osv_uses_pypi_for_python(self, factory):
        """_query_osv_api sends PyPI ecosystem when called with Python deps."""
        with patch('factory._requests.post') as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.json.return_value = {
                "results": [{"vulns": [{"id": "GHSA-8q59-q68h-6hv4", "aliases": []}]}]
            }
            result = factory._query_osv_api(
                [("PyYAML", "5.3.1"), ("requests", "2.25.0")],
                ecosystem="PyPI"
            )

        assert "GHSA-8q59-q68h-6hv4" in result
        call_body = mock_post.call_args[1]["json"]
        assert all(q["package"]["ecosystem"] == "PyPI" for q in call_body["queries"])

    def test_maven_ecosystem_still_used_for_java(self, factory):
        """_query_osv_api sends Maven ecosystem by default."""
        with patch('factory._requests.post') as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.json.return_value = {"results": [{"vulns": []}]}
            factory._query_osv_api([("com.example:lib", "1.0")], ecosystem="Maven")

        call_body = mock_post.call_args[1]["json"]
        assert all(q["package"]["ecosystem"] == "Maven" for q in call_body["queries"])


# ── Python pattern detection ──────────────────────────────────────────────────

class TestPythonPatterns:
    def test_always_includes_yaml_load_for_python(self):
        with patch('llm_client.genai'):
            from llm_client import SecurityAgentClient
            client = SecurityAgentClient.__new__(SecurityAgentClient)
            client.model_id = "test"
            client.client = MagicMock()
            client.client.models.generate_content.return_value.text = "[]"

            patterns = client.get_vulnerable_patterns([], build_system="python")
            assert "yaml.load(" in patterns

    def test_always_includes_pickle_for_python(self):
        with patch('llm_client.genai'):
            from llm_client import SecurityAgentClient
            client = SecurityAgentClient.__new__(SecurityAgentClient)
            client.model_id = "test"
            client.client = MagicMock()
            client.client.models.generate_content.return_value.text = "[]"

            patterns = client.get_vulnerable_patterns([], build_system="python")
            assert "pickle.loads(" in patterns

    def test_known_pyyaml_ghsa_maps_to_yaml_load(self):
        with patch('llm_client.genai'):
            from llm_client import SecurityAgentClient
            client = SecurityAgentClient.__new__(SecurityAgentClient)
            client.model_id = "test"
            client.client = MagicMock()

            patterns = client.get_vulnerable_patterns(
                ["GHSA-8q59-q68h-6hv4"], build_system="python"
            )
            assert "yaml.load(" in patterns

    def test_java_patterns_not_included_for_python_project(self):
        with patch('llm_client.genai'):
            from llm_client import SecurityAgentClient
            client = SecurityAgentClient.__new__(SecurityAgentClient)
            client.model_id = "test"
            client.client = MagicMock()
            client.client.models.generate_content.return_value.text = "[]"

            patterns = client.get_vulnerable_patterns([], build_system="python")
            # Java-specific patterns should not appear in Python-only scan
            assert "new Yaml()" not in patterns
            assert "enableDefaultTyping" not in patterns
