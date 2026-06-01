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
        gemini_key = os.getenv("GEMINI_API_KEY")
        if not gemini_key:
            print("Error: GEMINI_API_KEY not set in orchestrator environment.")
            return None

        container = self.client.containers.run(
            image=self.image_tag,
            command="/bin/bash",
            detach=True,
            tty=True,
            environment={
                "GITHUB_TOKEN": self.gh_token,
                "GEMINI_API_KEY": gemini_key
            }
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
                print("Error: No supported build file found (pom.xml / build.gradle / build.gradle.kts)")
                return None
            print(f"Detected build system: {build_system} ({build_file})")

            actor = RemediationActor(container, fork, build_system, build_file)

            # Use full transitive-dep scanning (OSV API) first, fall back to file scanner
            cves = self._scan_internal(container, workspace, build_system)
            if not cves:
                print("No vulnerabilities found — nothing to remediate.")
                return None

            verify_cmd = self._get_verify_command(build_system, container, workspace)
            build_error = None

            for attempt in range(1, MAX_PATCH_ATTEMPTS + 1):
                if attempt > 1:
                    if self._is_java_compile_error(build_error):
                        print(f"Retry {attempt}/{MAX_PATCH_ATTEMPTS}: Java compile errors — keeping build file, re-patching sources...")
                    else:
                        print(f"Retry {attempt}/{MAX_PATCH_ATTEMPTS}: build file error — restoring and re-patching...")
                        self._restore_build_files(container, workspace, build_system, build_file)

                if not actor.autonomous_patch(cves, build_error):
                    print("Patch generation failed.")
                    return None

                print(f"Verifying build with: {verify_cmd}")
                verify = container.exec_run(verify_cmd, workdir=workspace)
                if verify.exit_code == 0:
                    print("Build verified successfully.")
                    return actor.create_pull_request(cves)

                build_error = self._extract_build_error(verify.output.decode())
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
        1. Resolve ALL dependencies (direct + transitive) via Maven/Gradle,
           then query the OSV REST API — catches transitive CVEs.
        2. Fall back to OSV-Scanner file scan if dep resolution fails.
        """
        print("Resolving full dependency tree (including transitive)...")
        deps = self._resolve_all_dependencies(container, workspace, build_system)

        if deps:
            print(f"  Resolved {len(deps)} dependencies. Querying OSV API...")
            ghsa_ids = self._query_osv_api(deps)
            if ghsa_ids:
                return ghsa_ids
            print("  OSV API found no vulnerabilities in resolved deps.")

        # Fallback: scan build files directly with OSV-Scanner
        print("Falling back to OSV-Scanner file scan...")
        return self._scan_with_osv_scanner(container, workspace)

    def _resolve_all_dependencies(self, container, workspace, build_system) -> list:
        """
        Run the build tool's dependency resolution inside the sandbox and return
        a list of (group:artifact, version) tuples including transitive deps.
        """
        if build_system == "maven":
            result = container.exec_run(
                "mvn dependency:list -DincludeScope=runtime -q",
                workdir=workspace
            )
            if result.exit_code == 0:
                deps = self._parse_maven_dep_list(result.output.decode())
                if deps:
                    return deps
            # If resolution fails (e.g. compile error in project), still try to parse pom.xml
            print("  mvn dependency:list failed — falling back to declared deps only.")

        elif build_system == "gradle":
            # Gradle dep resolution requires internet and may be slow; try compileClasspath
            result = container.exec_run(
                "gradle dependencies --configuration compileClasspath --quiet 2>/dev/null",
                workdir=workspace
            )
            if result.exit_code == 0:
                deps = self._parse_gradle_dep_tree(result.output.decode())
                if deps:
                    return deps
            print("  gradle dependencies failed — falling back to declared deps only.")

        return []

    def _parse_maven_dep_list(self, output: str) -> list:
        """Parse `mvn dependency:list` output into (name, version) tuples."""
        deps = []
        for line in output.splitlines():
            # [INFO]    group:artifact:type:version:scope
            m = re.match(r'\[INFO\]\s+([^:\s]+):([^:\s]+):[^:]+:([^:]+):[^\s]+', line)
            if m:
                group, artifact, version = m.group(1), m.group(2), m.group(3)
                deps.append((f"{group}:{artifact}", version))
        return deps

    def _parse_gradle_dep_tree(self, output: str) -> list:
        """Parse `gradle dependencies` output into (name, version) tuples."""
        deps = []
        seen = set()
        for line in output.splitlines():
            # Lines like: +--- org.yaml:snakeyaml:1.28
            m = re.search(r'([a-zA-Z][^:\s]+):([^:\s]+):([^\s\(]+)', line)
            if m:
                group, artifact, version = m.group(1), m.group(2), m.group(3)
                # Strip -> markers (version conflict resolution)
                version = version.rstrip("(*)")
                key = f"{group}:{artifact}:{version}"
                if key not in seen and re.match(r'[\d]+\.', version):
                    seen.add(key)
                    deps.append((f"{group}:{artifact}", version))
        return deps

    def _query_osv_api(self, deps: list) -> list:
        """
        Query the OSV batch API for all resolved dependencies.
        Handles both Maven and generic ecosystems.
        Returns sorted unique GHSA IDs.
        """
        queries = [
            {"package": {"name": name, "ecosystem": "Maven"}, "version": version}
            for name, version in deps
        ]

        ghsa_ids = set()
        chunk_size = 100  # OSV API limit per batch

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

    def _is_java_compile_error(self, build_error: str) -> bool:
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
                    "cannot find symbol", "error:", "package does not exist")
        lines = raw_output.splitlines()
        error_lines = [l for l in lines if any(k in l for k in keywords)]
        tail = lines[-20:]
        combined = error_lines + [l for l in tail if l not in error_lines]
        return "\n".join(combined[:60])

    def _detect_build_system(self, container, workspace):
        if container.exec_run("test -f pom.xml", workdir=workspace).exit_code == 0:
            return "maven", "pom.xml"
        if container.exec_run("test -f build.gradle.kts", workdir=workspace).exit_code == 0:
            return "gradle", "build.gradle.kts"
        if container.exec_run("test -f build.gradle", workdir=workspace).exit_code == 0:
            return "gradle", "build.gradle"
        return None, None

    def _get_verify_command(self, build_system, container, workspace):
        if build_system == "maven":
            return "mvn clean compile"
        if container.exec_run("test -f gradlew", workdir=workspace).exit_code == 0:
            return "./gradlew compileJava"
        return "gradle compileJava"
