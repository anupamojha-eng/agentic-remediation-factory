"""Unit tests for OSV-Scanner output parsing in _scan_internal. No external deps."""
import sys
import os
import json
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'orchestrator'))


def make_exec_result(exit_code, stdout=None, stderr=None):
    r = MagicMock()
    r.exit_code = exit_code
    r.output = (
        stdout.encode() if isinstance(stdout, str) else stdout,
        stderr.encode() if isinstance(stderr, str) else stderr,
    )
    return r


OSV_WITH_GHSA = json.dumps({
    "results": [{
        "source": {"path": "pom.xml", "type": "lockfile"},
        "packages": [{
            "package": {
                "name": "com.fasterxml.jackson.core:jackson-databind",
                "version": "2.13.0",
                "ecosystem": "Maven"
            },
            "vulnerabilities": [
                {
                    "id": "GHSA-jjjh-jjxp-wpff",
                    "aliases": ["CVE-2022-42003"]
                },
                {
                    "id": "GHSA-rgv9-q543-rqg4",
                    "aliases": ["CVE-2022-42004"]
                }
            ]
        }]
    }]
})

OSV_WITH_CVE_PRIMARY = json.dumps({
    "results": [{
        "source": {"path": "pom.xml", "type": "lockfile"},
        "packages": [{
            "package": {"name": "log4j:log4j", "version": "1.2.17", "ecosystem": "Maven"},
            "vulnerabilities": [{
                "id": "CVE-2019-17571",
                "aliases": ["GHSA-f7vh-qwp3-x37m"]
            }]
        }]
    }]
})

OSV_EMPTY = json.dumps({"results": []})


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


class TestScanInternal:
    def test_extracts_ghsa_ids_from_scan_output(self, factory, container):
        container.exec_run.return_value = make_exec_result(1, stdout=OSV_WITH_GHSA)
        result = factory._scan_internal(container, "/ws")
        assert "GHSA-jjjh-jjxp-wpff" in result
        assert "GHSA-rgv9-q543-rqg4" in result

    def test_extracts_ghsa_id_from_cve_alias(self, factory, container):
        container.exec_run.return_value = make_exec_result(1, stdout=OSV_WITH_CVE_PRIMARY)
        result = factory._scan_internal(container, "/ws")
        assert "GHSA-f7vh-qwp3-x37m" in result

    def test_returns_empty_list_when_no_vulns(self, factory, container):
        container.exec_run.return_value = make_exec_result(0, stdout=OSV_EMPTY)
        result = factory._scan_internal(container, "/ws")
        assert result == []

    def test_returns_empty_list_on_scanner_error(self, factory, container):
        container.exec_run.return_value = make_exec_result(2, stdout=None, stderr="permission denied")
        result = factory._scan_internal(container, "/ws")
        assert result == []

    def test_returns_empty_list_on_empty_stdout(self, factory, container):
        container.exec_run.return_value = make_exec_result(0, stdout=None)
        result = factory._scan_internal(container, "/ws")
        assert result == []

    def test_returns_empty_list_on_malformed_json(self, factory, container):
        container.exec_run.return_value = make_exec_result(1, stdout="not json at all")
        result = factory._scan_internal(container, "/ws")
        assert result == []

    def test_deduplicates_ghsa_ids(self, factory, container):
        # Same GHSA appearing as primary and alias in different vulns
        osv_data = json.dumps({
            "results": [{
                "source": {"path": "pom.xml", "type": "lockfile"},
                "packages": [{
                    "package": {"name": "foo", "version": "1.0", "ecosystem": "Maven"},
                    "vulnerabilities": [
                        {"id": "GHSA-aaaa-bbbb-cccc", "aliases": []},
                        {"id": "CVE-2022-1234", "aliases": ["GHSA-aaaa-bbbb-cccc"]},
                    ]
                }]
            }]
        })
        container.exec_run.return_value = make_exec_result(1, stdout=osv_data)
        result = factory._scan_internal(container, "/ws")
        assert result.count("GHSA-aaaa-bbbb-cccc") == 1

    def test_returns_sorted_list(self, factory, container):
        container.exec_run.return_value = make_exec_result(1, stdout=OSV_WITH_GHSA)
        result = factory._scan_internal(container, "/ws")
        assert result == sorted(result)

    def test_passes_workspace_to_exec_run(self, factory, container):
        container.exec_run.return_value = make_exec_result(0, stdout=OSV_EMPTY)
        factory._scan_internal(container, "/custom/workspace")
        container.exec_run.assert_called_once_with(
            "osv-scanner --format json .",
            workdir="/custom/workspace",
            demux=True
        )
