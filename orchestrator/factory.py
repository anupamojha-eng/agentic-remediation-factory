import docker
import json
import os
import re
import requests as _requests
from github import Github, Auth
from remediator import RemediationActor

MAX_PATCH_ATTEMPTS = 3

# OSV batch API endpoint
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# OSV ecosystem per build system
_ECOSYSTEM = {
    "maven":  "Maven",
    "gradle": "Maven",
    "python": "PyPI",
    "go":     "Go",
    "rust":   "crates.io",
}


class RemediationFactory:
    def __init__(self):
        self.client = docker.from_env()
        self.image_tag = "cve-fixer-sandbox:latest"
        self.gh_token = os.getenv("GITHUB_TOKEN")
        if not self.gh_token:
            print("WARNING: GITHUB_TOKEN not found in environment.")

    def build_sandbox(self):
        """Build the cve-fixer-sandbox image from sandbox/Dockerfile."""
        sandbox_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sandbox"
        )
        print(f"Building sandbox image from {sandbox_dir} ...")
        image, logs = self.client.images.build(path=sandbox_dir, tag=self.image_tag, rm=True)
        for chunk in logs:
            if "stream" in chunk:
                print(chunk["stream"], end="", flush=True)
        print(f"Sandbox image ready: {self.image_tag}")
        return image

    def execute_ephemeral_fix(self, upstream_url: str, target_tag: str):
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        gemini_key = os.getenv("GEMINI_API_KEY")
        if not anthropic_key and not gemini_key:
            print("Error: set ANTHROPIC_API_KEY (Claude) or GEMINI_API_KEY (Gemini).")
            return None

        # Pass whichever keys are present so the container environment mirrors
        # the host — the LLM client itself (running on host) reads these directly.
        env = {"GITHUB_TOKEN": self.gh_token}
        if anthropic_key:
            env["ANTHROPIC_API_KEY"] = anthropic_key
        if gemini_key:
            env["GEMINI_API_KEY"] = gemini_key
        llm_provider = os.getenv("LLM_PROVIDER")
        if llm_provider:
            env["LLM_PROVIDER"] = llm_provider

        container = self.client.containers.run(
            image=self.image_tag,
            command="/bin/bash",
            detach=True,
            tty=True,
            environment=env,
        )
        try:
            auth = Auth.Token(self.gh_token)
            gh = Github(auth=auth)

            clean_url = upstream_url.strip().rstrip("/")
            repo_path = clean_url.split("github.com/")[-1].replace(".git", "")
            print(f"Accessing {repo_path}...")

            repo = gh.get_repo(repo_path)
            fork = repo.create_fork()
            print(f"Fork ready at {fork.html_url}")

            auth_url = fork.clone_url.replace("https://", f"https://{self.gh_token}@")
            workspace = "/home/agent/workspace"

            container.exec_run(f"rm -rf {workspace}", workdir="/")
            container.exec_run(f"mkdir -p {workspace}", workdir="/")

            clone_res = container.exec_run(f"git clone {auth_url} {workspace}", workdir="/")
            if clone_res.exit_code != 0:
                print(f"Git Clone Failed: {clone_res.output.decode()}")
                return None

            container.exec_run(f"git remote add upstream {upstream_url}", workdir=workspace)
            container.exec_run("git fetch upstream --tags", workdir=workspace)
            container.exec_run(f"git checkout {target_tag}", workdir=workspace)

            build_system, build_file = self._detect_build_system(container, workspace)
            if not build_system:
                print("Error: No supported build file found")
                return None
            print(f"Detected build system: {build_system} ({build_file})")

            actor = RemediationActor(container, fork, build_system, build_file)
            cves = self._scan_internal(container, workspace, build_system)
            if not cves:
                print("No vulnerabilities found — nothing to remediate.")
                return None

            verify_cmd = self._get_verify_command(build_system, container, workspace)
            build_error = None

            for attempt in range(1, MAX_PATCH_ATTEMPTS + 1):
                if attempt > 1:
                    if self._is_source_compile_error(build_error, build_system):
                        print(f"Retry {attempt}/{MAX_PATCH_ATTEMPTS}: source errors — keeping build file, re-patching sources...")
                    else:
                        print(f"Retry {attempt}/{MAX_PATCH_ATTEMPTS}: build file error — restoring and re-patching...")
                        self._restore_build_files(container, workspace, build_system, build_file)

                if not actor.autonomous_patch(cves, build_error):
                    print("Patch generation failed.")
                    return None

                print(f"Verifying build with: {verify_cmd}")
                verify = container.exec_run(["bash", "-c", verify_cmd], workdir=workspace)
                verify_output = verify.output.decode("utf-8", errors="replace")
                if verify.exit_code == 0:
                    print("Build verified successfully.")
                    actor.audit["attempt"] = attempt
                    actor.audit["build_output"] = verify_output
                    return actor.create_pull_request(cves)

                build_error = self._extract_build_error(verify_output)
                print(f"Build failed (attempt {attempt}/{MAX_PATCH_ATTEMPTS}):\n{build_error}")

            print(f"Build still failing after {MAX_PATCH_ATTEMPTS} attempts — giving up.")
            return None
        finally:
            container.stop()
            container.remove()

    # ── Scanning ──────────────────────────────────────────────────────────────

    def _scan_internal(self, container, workspace="/home/agent/workspace", build_system=None):
        """
        Two-phase vulnerability scanning:
        1. Resolve ALL dependencies (direct + transitive) via build tool,
           then query the OSV REST API — catches transitive CVEs.
        2. Fall back to OSV-Scanner file scan if dep resolution fails.
        """
        print("Resolving full dependency tree (including transitive)...")
        ecosystem = _ECOSYSTEM.get(build_system, "Maven")
        deps = self._resolve_all_dependencies(container, workspace, build_system)

        if deps:
            print(f"  Resolved {len(deps)} dependencies. Querying OSV API...")
            ghsa_ids = self._query_osv_api(deps, ecosystem)
            if ghsa_ids:
                return ghsa_ids
            print("  OSV API found no vulnerabilities in resolved deps.")

        print("Falling back to OSV-Scanner file scan...")
        return self._scan_with_osv_scanner(container, workspace)

    def _resolve_all_dependencies(self, container, workspace, build_system) -> list:
        """Resolve full dep tree including transitive deps for all supported build systems."""
        if build_system == "maven":
            result = container.exec_run(
                "mvn dependency:list -DincludeScope=runtime -q",
                workdir=workspace
            )
            if result.exit_code == 0:
                deps = self._parse_maven_dep_list(result.output.decode())
                if deps:
                    return deps
            print("  mvn dependency:list failed — falling back to declared deps only.")

        elif build_system == "gradle":
            result = container.exec_run(
                "gradle dependencies --configuration compileClasspath --quiet 2>/dev/null",
                workdir=workspace
            )
            if result.exit_code == 0:
                deps = self._parse_gradle_dep_tree(result.output.decode())
                if deps:
                    return deps
            print("  gradle dependencies failed — falling back to declared deps only.")

        elif build_system == "python":
            # Install all deps (including transitive), then list everything installed
            build_file = "requirements.txt"
            if container.exec_run("test -f Pipfile", workdir=workspace).exit_code == 0:
                build_file = "Pipfile"
            elif container.exec_run("test -f pyproject.toml", workdir=workspace).exit_code == 0:
                build_file = "pyproject.toml"

            if build_file == "requirements.txt":
                install_cmd = "pip3 install --user -r requirements.txt -q"
            elif build_file == "Pipfile":
                install_cmd = "pip3 install --user pipenv -q && pipenv install -q"
            else:
                install_cmd = "pip3 install --user . -q"

            install = container.exec_run(install_cmd, workdir=workspace)
            if install.exit_code == 0:
                result = container.exec_run(
                    ["pip3", "list", "--format=json"],
                    workdir=workspace
                )
                if result.exit_code == 0:
                    deps = self._parse_python_pip_list(result.output.decode())
                    if deps:
                        return deps
            print("  pip3 install failed — falling back to declared deps only.")

        return []

    def _parse_maven_dep_list(self, output: str) -> list:
        deps = []
        for line in output.splitlines():
            m = re.match(r'\[INFO\]\s+([^:\s]+):([^:\s]+):[^:]+:([^:]+):[^\s]+', line)
            if m:
                group, artifact, version = m.group(1), m.group(2), m.group(3)
                deps.append((f"{group}:{artifact}", version))
        return deps

    def _parse_gradle_dep_tree(self, output: str) -> list:
        deps = []
        seen = set()
        for line in output.splitlines():
            m = re.search(r'([a-zA-Z][^:\s]+):([^:\s]+):([^\s\(]+)', line)
            if m:
                group, artifact, version = m.group(1), m.group(2), m.group(3)
                version = version.rstrip("(*)")
                key = f"{group}:{artifact}:{version}"
                if key not in seen and re.match(r'[\d]+\.', version):
                    seen.add(key)
                    deps.append((f"{group}:{artifact}", version))
        return deps

    def _parse_python_pip_list(self, output: str) -> list:
        """Parse `pip3 list --format=json` output into (name, version) tuples."""
        try:
            packages = json.loads(output)
            return [(p["name"], p["version"]) for p in packages]
        except (json.JSONDecodeError, KeyError):
            return []

    def _query_osv_api(self, deps: list, ecosystem: str = "Maven") -> list:
        """Query the OSV batch API for vulnerabilities across the full dep tree."""
        queries = [
            {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            for name, version in deps
        ]

        ghsa_ids = set()
        chunk_size = 100

        for i in range(0, len(queries), chunk_size):
            batch = queries[i:i + chunk_size]
            try:
                resp = _requests.post(
                    _OSV_BATCH_URL,
                    json={"queries": batch},
                    timeout=30
                )
                if not resp.ok:
                    print(f"  OSV API error: HTTP {resp.status_code}")
                    continue

                for result in resp.json().get("results", []):
                    for vuln in result.get("vulns", []):
                        vid = vuln.get("id", "")
                        if vid.startswith("GHSA-"):
                            ghsa_ids.add(vid)
                        for alias in vuln.get("aliases", []):
                            if alias.startswith("GHSA-"):
                                ghsa_ids.add(alias)
            except Exception as e:
                print(f"  OSV API request failed: {e}")

        if ghsa_ids:
            print(f"Vulnerabilities found (transitive scan): {', '.join(sorted(ghsa_ids))}")
        return sorted(ghsa_ids)

    def _scan_with_osv_scanner(self, container, workspace) -> list:
        """OSV-Scanner file scan — declared dependencies only, used as fallback."""
        scan = container.exec_run(
            "osv-scanner --format json .",
            workdir=workspace,
            demux=True
        )
        stdout, stderr = scan.output

        if scan.exit_code > 1:
            err = stderr.decode("utf-8", errors="replace") if stderr else "(no stderr)"
            print(f"OSV-Scanner error (exit {scan.exit_code}): {err[:300]}")
            return []

        if not stdout:
            print("OSV-Scanner produced no output.")
            return []

        try:
            data = json.loads(stdout.decode("utf-8", errors="replace").strip())
        except json.JSONDecodeError as e:
            print(f"Failed to parse OSV-Scanner JSON: {e}")
            return []

        ghsa_ids = set()
        for result in data.get("results", []):
            for pkg in result.get("packages", []):
                for vuln in pkg.get("vulnerabilities", []):
                    vid = vuln.get("id", "")
                    if vid.startswith("GHSA-"):
                        ghsa_ids.add(vid)
                    for alias in vuln.get("aliases", []):
                        if alias.startswith("GHSA-"):
                            ghsa_ids.add(alias)

        if ghsa_ids:
            print(f"Vulnerabilities found (file scan): {', '.join(sorted(ghsa_ids))}")
        else:
            print("OSV-Scanner found no GHSA vulnerabilities.")
        return sorted(ghsa_ids)

    # ── Build system helpers ──────────────────────────────────────────────────

    def _is_source_compile_error(self, build_error: str, build_system: str = None) -> bool:
        """True when errors are in source files (not in the build file itself)."""
        if build_system == "python":
            # Python errors look like:  File "path.py", line N
            has_py = bool(re.search(r'File ".*\.py"', build_error or ""))
            has_pkg_error = any(k in (build_error or "") for k in (
                "No matching distribution", "ERROR: Could not find a version",
                "ResolutionImpossible"
            ))
            return has_py and not has_pkg_error
        # Java / Groovy
        has_java = bool(re.search(r'\S+\.java:\[?\d+', build_error or ""))
        has_build_file_parse = any(k in (build_error or "") for k in (
            "Non-parseable POM", "ProjectBuildingException", "Invalid POM",
            "could not resolve", "dependency resolution"
        ))
        return has_java and not has_build_file_parse

    def _restore_build_files(self, container, workspace, build_system, build_file):
        container.exec_run(f"git checkout HEAD -- {build_file}", workdir=workspace)
        if build_system == "gradle":
            container.exec_run(
                "git checkout HEAD -- gradle/libs.versions.toml 2>/dev/null || true",
                workdir=workspace
            )

    def _extract_build_error(self, raw_output: str) -> str:
        keywords = ("[ERROR]", "[FATAL]", "BUILD FAILURE", "COMPILATION ERROR",
                    "cannot find symbol", "error:", "package does not exist",
                    "ERROR:", "Traceback", "SyntaxError", "ImportError",
                    "No matching distribution")
        lines = raw_output.splitlines()
        error_lines = [l for l in lines if any(k in l for k in keywords)]
        tail = lines[-20:]
        combined = error_lines + [l for l in tail if l not in error_lines]
        return "\n".join(combined[:60])

    def _detect_build_system(self, container, workspace):
        # JVM
        if container.exec_run("test -f pom.xml", workdir=workspace).exit_code == 0:
            return "maven", "pom.xml"
        if container.exec_run("test -f build.gradle.kts", workdir=workspace).exit_code == 0:
            return "gradle", "build.gradle.kts"
        if container.exec_run("test -f build.gradle", workdir=workspace).exit_code == 0:
            return "gradle", "build.gradle"
        # Python
        if container.exec_run("test -f requirements.txt", workdir=workspace).exit_code == 0:
            return "python", "requirements.txt"
        if container.exec_run("test -f Pipfile", workdir=workspace).exit_code == 0:
            return "python", "Pipfile"
        if container.exec_run("test -f pyproject.toml", workdir=workspace).exit_code == 0:
            return "python", "pyproject.toml"
        return None, None

    def _get_verify_command(self, build_system, container, workspace):
        if build_system == "maven":
            return "mvn clean compile"
        if build_system == "python":
            # Install deps and run tests if they exist; otherwise just check install
            has_pytest = container.exec_run(
                ["bash", "-c", "test -d tests || test -f pytest.ini || test -f setup.cfg"],
                workdir=workspace
            ).exit_code == 0
            if has_pytest:
                return "pip3 install --user -r requirements.txt pytest -q && python3 -m pytest -q --tb=short 2>&1"
            return "pip3 install --user -r requirements.txt -q && pip3 check"
        # Gradle
        if container.exec_run("test -f gradlew", workdir=workspace).exit_code == 0:
            return "./gradlew compileJava"
        return "gradle compileJava"
