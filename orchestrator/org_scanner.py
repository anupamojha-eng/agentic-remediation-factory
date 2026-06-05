"""
Sentinel org scanner — scans all repos in a GitHub org for CVEs.

Two modes:
  quick (default): reads build files via GitHub API, queries OSV directly.
                   No Docker required. Fast enough to scan 50+ repos in minutes.
  full:            spins up the full Docker sandbox per repo for transitive
                   dep resolution. Accurate but slow. Used with --create-prs.

Usage:
    from org_scanner import OrgScanner
    scanner = OrgScanner(gh_token="...")
    results = scanner.scan(org="my-org", filters={...})
"""

import fnmatch
import json
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

import requests as _requests
from github import Github, Auth

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

_ECOSYSTEM_MAP = {
    "Java":   "Maven",
    "Kotlin": "Maven",
    "Python": "PyPI",
}


@dataclass
class Cvefinding:
    ghsa_id: str
    severity: str = "UNKNOWN"
    summary: str = ""
    affected_package: str = ""
    affected_version: str = ""
    fixed_version: str = ""


@dataclass
class RepoResult:
    name: str
    full_name: str
    html_url: str
    language: str
    build_system: str
    default_branch: str
    is_fork: bool
    is_archived: bool
    findings: list[Cvefinding] = field(default_factory=list)
    pr_url: str = ""
    scan_error: str = ""
    skipped: bool = False
    skip_reason: str = ""

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "NONE"
        return min(self.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 4)).severity

    @property
    def affected(self) -> bool:
        return len(self.findings) > 0


class OrgScanner:
    def __init__(self, gh_token: str, github_url: str = "https://api.github.com"):
        auth = Auth.Token(gh_token)
        if github_url != "https://api.github.com":
            from github import GithubEnterprise
            self.gh = GithubEnterprise(base_url=github_url, auth=auth)
        else:
            self.gh = Github(auth=auth)
        self.gh_token = gh_token

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(
        self,
        org: str,
        languages: list[str] | None = None,
        severities: list[str] | None = None,
        include_pattern: str | None = None,
        exclude_pattern: str | None = None,
        max_repos: int = 100,
        skip_forks: bool = True,
        skip_archived: bool = True,
        on_progress=None,
    ) -> list[RepoResult]:
        """
        Scan all repos in an org. Returns one RepoResult per repo.
        on_progress(current, total, result) called after each repo.
        """
        org_obj = self.gh.get_organization(org)
        all_repos = list(org_obj.get_repos(type="all"))

        # Filter
        repos = []
        for r in all_repos:
            if len(repos) >= max_repos:
                break
            if skip_forks and r.fork:
                continue
            if skip_archived and r.archived:
                continue
            if languages:
                repo_lang = (r.language or "").lower()
                if not any(repo_lang == lang.lower() for lang in languages):
                    continue
            if include_pattern and not fnmatch.fnmatch(r.name, include_pattern):
                continue
            if exclude_pattern and fnmatch.fnmatch(r.name, exclude_pattern):
                continue
            repos.append(r)

        print(f"  Scanning {len(repos)} repos in {org} "
              f"(filtered from {len(all_repos)} total) ...")

        results = []
        for i, repo in enumerate(repos):
            result = self._scan_repo_quick(repo)

            # Filter by severity if requested
            if severities and result.findings:
                result.findings = [
                    f for f in result.findings
                    if f.severity.upper() in [s.upper() for s in severities]
                ]

            results.append(result)
            if on_progress:
                on_progress(i + 1, len(repos), result)

        return results

    def create_prs_for_results(
        self,
        results: list[RepoResult],
        branch: str = "main",
        severities: list[str] | None = None,
    ) -> list[RepoResult]:
        """
        Run full Docker-based remediation for repos with findings.
        Updates result.pr_url in place. Returns updated results.
        """
        from factory import RemediationFactory
        factory = RemediationFactory()

        affected = [
            r for r in results
            if r.affected and not r.pr_url and not r.scan_error
        ]
        if severities:
            affected = [
                r for r in affected
                if r.max_severity.upper() in [s.upper() for s in severities]
            ]

        print(f"\n  Creating PRs for {len(affected)} affected repo(s)...")
        for r in affected:
            try:
                print(f"    Remediating {r.full_name} ...")
                pr_url = factory.execute_ephemeral_fix(r.html_url, branch)
                r.pr_url = pr_url or ""
                if pr_url:
                    print(f"    ✅ PR: {pr_url}")
                else:
                    r.scan_error = "Remediation failed — check logs"
                    print(f"    ❌ Remediation failed for {r.full_name}")
            except Exception as e:
                r.scan_error = str(e)[:200]
                print(f"    ❌ Error: {e}")

        return results

    # ── Quick scan (no Docker) ────────────────────────────────────────────────

    def _scan_repo_quick(self, repo) -> RepoResult:
        result = RepoResult(
            name=repo.name,
            full_name=repo.full_name,
            html_url=repo.html_url,
            language=repo.language or "Unknown",
            build_system="unknown",
            default_branch=repo.default_branch or "main",
            is_fork=repo.fork,
            is_archived=repo.archived,
        )

        try:
            build_system, deps = self._detect_and_extract_deps(repo)
            result.build_system = build_system

            if not deps:
                result.skipped = True
                result.skip_reason = "No supported build file found"
                return result

            ecosystem = _ECOSYSTEM_MAP.get(repo.language or "", "Maven")
            vulns = self._query_osv(deps, ecosystem)
            result.findings = vulns

        except Exception as e:
            result.scan_error = str(e)[:300]

        return result

    def _detect_and_extract_deps(self, repo) -> tuple[str, list[tuple[str, str]]]:
        """Try to read build files via GitHub contents API and extract deps."""
        branch = repo.default_branch or "main"

        # Maven
        try:
            content = self._get_file(repo, "pom.xml", branch)
            if content:
                return "maven", self._parse_pom(content)
        except Exception:
            pass

        # Python requirements.txt
        try:
            content = self._get_file(repo, "requirements.txt", branch)
            if content:
                return "python", self._parse_requirements(content)
        except Exception:
            pass

        # pyproject.toml
        try:
            content = self._get_file(repo, "pyproject.toml", branch)
            if content:
                return "python", self._parse_pyproject(content)
        except Exception:
            pass

        # Gradle — parse build.gradle for declared deps
        try:
            content = self._get_file(repo, "build.gradle", branch)
            if content:
                return "gradle", self._parse_gradle(content)
        except Exception:
            pass

        return "unknown", []

    def _get_file(self, repo, path: str, branch: str) -> str | None:
        import base64
        try:
            f = repo.get_contents(path, ref=branch)
            if f.encoding == "base64":
                return base64.b64decode(f.content).decode("utf-8", errors="replace")
            return f.decoded_content.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _parse_pom(self, content: str) -> list[tuple[str, str]]:
        deps = []
        try:
            root = ET.fromstring(content)
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            for dep in root.findall(".//m:dependency", ns):
                g = dep.findtext("m:groupId", namespaces=ns, default="")
                a = dep.findtext("m:artifactId", namespaces=ns, default="")
                v = dep.findtext("m:version", namespaces=ns, default="")
                if g and a and v and not v.startswith("$"):
                    deps.append((f"{g}:{a}", v))
        except ET.ParseError:
            pass
        return deps

    def _parse_requirements(self, content: str) -> list[tuple[str, str]]:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r'^([A-Za-z0-9_.\-]+)[=><!\[]+([A-Za-z0-9_.]+)', line)
            if m:
                deps.append((m.group(1), m.group(2)))
        return deps

    def _parse_pyproject(self, content: str) -> list[tuple[str, str]]:
        deps = []
        in_deps = False
        for line in content.splitlines():
            if "dependencies" in line and "[" in line:
                in_deps = True
                continue
            if in_deps:
                if line.strip().startswith("["):
                    break
                m = re.search(r'"([A-Za-z0-9_.\-]+)[>=<!\[]+([A-Za-z0-9_.]+)', line)
                if m:
                    deps.append((m.group(1), m.group(2)))
        return deps

    def _parse_gradle(self, content: str) -> list[tuple[str, str]]:
        deps = []
        for m in re.finditer(
            r"""['"]([a-zA-Z][^'":\s]+):([^'":\s]+):([^'":\s]+)['"]""", content
        ):
            group, artifact, version = m.group(1), m.group(2), m.group(3)
            if re.match(r'\d+\.', version):
                deps.append((f"{group}:{artifact}", version))
        return deps

    # ── OSV query ─────────────────────────────────────────────────────────────

    def _query_osv(self, deps: list[tuple[str, str]], ecosystem: str) -> list[Cvefinding]:
        if not deps:
            return []

        queries = [
            {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            for name, version in deps
        ]

        findings = []
        chunk_size = 100
        for i in range(0, len(queries), chunk_size):
            batch = queries[i:i + chunk_size]
            batch_deps = deps[i:i + chunk_size]
            try:
                resp = _requests.post(
                    _OSV_BATCH_URL, json={"queries": batch}, timeout=30
                )
                if not resp.ok:
                    continue
                for j, result in enumerate(resp.json().get("results", [])):
                    pkg_name, pkg_ver = batch_deps[j]
                    for vuln in result.get("vulns", []):
                        ghsa = self._extract_ghsa(vuln)
                        if not ghsa:
                            continue
                        severity = self._extract_severity(vuln)
                        summary = vuln.get("summary", "")[:120]
                        fixed = self._extract_fixed_version(vuln, pkg_name)
                        findings.append(Cvefinding(
                            ghsa_id=ghsa,
                            severity=severity,
                            summary=summary,
                            affected_package=pkg_name,
                            affected_version=pkg_ver,
                            fixed_version=fixed,
                        ))
            except Exception as e:
                print(f"    OSV query error: {e}")
            time.sleep(0.1)

        # Deduplicate by GHSA ID
        seen = set()
        unique = []
        for f in findings:
            if f.ghsa_id not in seen:
                seen.add(f.ghsa_id)
                unique.append(f)

        return sorted(unique, key=lambda f: _SEVERITY_ORDER.get(f.severity, 4))

    def _extract_ghsa(self, vuln: dict) -> str:
        vid = vuln.get("id", "")
        if vid.startswith("GHSA-"):
            return vid
        for alias in vuln.get("aliases", []):
            if alias.startswith("GHSA-"):
                return alias
        return ""

    def _extract_severity(self, vuln: dict) -> str:
        db = vuln.get("database_specific", {})
        sev = db.get("severity", "").upper()
        if sev in _SEVERITY_ORDER:
            return sev
        for s in vuln.get("severity", []):
            score = s.get("score", "")
            if "CVSS" in score:
                return self._cvss_to_severity(score)
        return "UNKNOWN"

    def _cvss_to_severity(self, score: str) -> str:
        m = re.search(r'/AV:[^/]+/.+?/([0-9.]+)$', score)
        if not m:
            m = re.search(r'(\d+\.\d+)$', score)
        if m:
            v = float(m.group(1))
            if v >= 9.0: return "CRITICAL"
            if v >= 7.0: return "HIGH"
            if v >= 4.0: return "MEDIUM"
            return "LOW"
        return "UNKNOWN"

    def _extract_fixed_version(self, vuln: dict, pkg: str) -> str:
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        return ev["fixed"]
        return ""
