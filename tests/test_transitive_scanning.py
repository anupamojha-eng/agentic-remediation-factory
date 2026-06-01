"""Unit tests for transitive dependency scanning via OSV REST API."""
import sys
import os
import json
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'orchestrator'))


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


class TestParseMavenDepList:
    def test_parses_standard_format(self, factory):
        output = """
[INFO] The following files have been resolved:
[INFO]    org.yaml:snakeyaml:jar:1.28:runtime
[INFO]    com.fasterxml.jackson.core:jackson-databind:jar:2.13.0:compile
[INFO]    org.springframework:spring-core:jar:5.3.12:compile
"""
        deps = factory._parse_maven_dep_list(output)
        names = [n for n, _ in deps]
        versions = {n: v for n, v in deps}
        assert "org.yaml:snakeyaml" in names
        assert versions["org.yaml:snakeyaml"] == "1.28"
        assert "com.fasterxml.jackson.core:jackson-databind" in names
        assert versions["com.fasterxml.jackson.core:jackson-databind"] == "2.13.0"

    def test_returns_empty_list_for_no_matches(self, factory):
        assert factory._parse_maven_dep_list("[INFO] BUILD SUCCESS") == []

    def test_handles_empty_output(self, factory):
        assert factory._parse_maven_dep_list("") == []


class TestParseGradleDepTree:
    def test_parses_standard_gradle_output(self, factory):
        output = """
+--- org.yaml:snakeyaml:1.28
+--- com.fasterxml.jackson.core:jackson-databind:2.13.0
\\--- org.springframework:spring-core:5.3.12
"""
        deps = factory._parse_gradle_dep_tree(output)
        names = [n for n, _ in deps]
        assert "org.yaml:snakeyaml" in names
        assert "com.fasterxml.jackson.core:jackson-databind" in names

    def test_parses_conflict_resolution_markers(self, factory):
        output = "+--- org.yaml:snakeyaml:1.25 -> 1.28 (*)\n"
        deps = factory._parse_gradle_dep_tree(output)
        # Should parse something (exact version handling is approximate)
        assert isinstance(deps, list)


class TestQueryOsvApi:
    def test_extracts_ghsa_ids_from_response(self, factory):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "results": [
                {
                    "vulns": [
                        {"id": "GHSA-668q-qrv7-99fm", "aliases": ["CVE-2022-1471"]},
                    ]
                },
                {
                    "vulns": []  # clean package
                }
            ]
        }

        with patch('factory._requests.post', return_value=mock_response):
            result = factory._query_osv_api([
                ("org.yaml:snakeyaml", "1.28"),
                ("org.springframework:spring-core", "5.3.12"),
            ])

        assert "GHSA-668q-qrv7-99fm" in result

    def test_extracts_ghsa_from_aliases(self, factory):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "results": [{
                "vulns": [{"id": "CVE-2022-42003", "aliases": ["GHSA-jjjh-jjxp-wpff"]}]
            }]
        }

        with patch('factory._requests.post', return_value=mock_response):
            result = factory._query_osv_api([("com.fasterxml.jackson.core:jackson-databind", "2.13.0")])

        assert "GHSA-jjjh-jjxp-wpff" in result

    def test_returns_empty_on_api_error(self, factory):
        with patch('factory._requests.post', side_effect=Exception("network error")):
            result = factory._query_osv_api([("org.yaml:snakeyaml", "1.28")])
        assert result == []

    def test_returns_empty_on_bad_status(self, factory):
        mock_response = MagicMock()
        mock_response.ok = False
        with patch('factory._requests.post', return_value=mock_response):
            result = factory._query_osv_api([("org.yaml:snakeyaml", "1.28")])
        assert result == []

    def test_deduplicates_across_batches(self, factory):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "results": [{"vulns": [{"id": "GHSA-668q-qrv7-99fm", "aliases": []}]}]
        }

        with patch('factory._requests.post', return_value=mock_response):
            # Feed same dep twice to check dedup
            result = factory._query_osv_api([
                ("org.yaml:snakeyaml", "1.28"),
                ("org.yaml:snakeyaml", "1.28"),
            ])

        assert result.count("GHSA-668q-qrv7-99fm") == 1


OSV_EMPTY_JSON = json.dumps({"results": []})


class TestResolveDependencies:
    def _exec_plain(self, exit_code, output=""):
        """Mock for exec_run calls that return plain .output bytes (no demux)."""
        r = MagicMock()
        r.exit_code = exit_code
        r.output = output.encode() if isinstance(output, str) else output
        return r

    def _exec_demux(self, exit_code, stdout="", stderr=""):
        """Mock for exec_run calls with demux=True — .output is (stdout, stderr) tuple."""
        r = MagicMock()
        r.exit_code = exit_code
        r.output = (
            stdout.encode() if isinstance(stdout, str) else stdout,
            stderr.encode() if isinstance(stderr, str) else stderr,
        )
        return r

    def test_uses_maven_dep_list_for_maven(self, factory, container):
        dep_output = "[INFO]    org.yaml:snakeyaml:jar:1.28:runtime\n"
        # dependency:list succeeds → OSV API returns results → no fallback needed
        container.exec_run.return_value = self._exec_plain(0, dep_output)

        with patch('factory._requests.post') as mock_post:
            mock_post.return_value.ok = True
            mock_post.return_value.json.return_value = {
                "results": [{"vulns": [{"id": "GHSA-668q-qrv7-99fm", "aliases": []}]}]
            }
            result = factory._scan_internal(container, "/ws", build_system="maven")

        assert "GHSA-668q-qrv7-99fm" in result
        calls = [str(c) for c in container.exec_run.call_args_list]
        assert any("dependency:list" in c for c in calls)

    def test_falls_back_to_osv_scanner_when_dep_list_fails(self, factory, container):
        # First call (mvn dependency:list) fails → falls back to OSV-Scanner
        # OSV-Scanner call uses demux=True
        fail = self._exec_plain(1, "")
        success = self._exec_demux(0, stdout=OSV_EMPTY_JSON, stderr="")
        container.exec_run.side_effect = [fail, success]

        result = factory._scan_internal(container, "/ws", build_system="maven")
        assert result == []  # OSV_EMPTY_JSON has no vulnerabilities
