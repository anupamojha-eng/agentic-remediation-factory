import docker
import json
import os
from github import Github, Auth
from remediator import RemediationActor

MAX_PATCH_ATTEMPTS = 3


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
            # create_fork returns the existing fork if one already exists — that's fine
            print(f"Fork ready at {fork.html_url}")

            auth_url = fork.clone_url.replace("https://", f"https://{self.gh_token}@")
            workspace = "/home/agent/workspace"

            # Run setup from / — workspace may not exist yet (WORKDIR deleted by rm -rf)
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
            cves = self._scan_internal(container, workspace)
            if not cves:
                print("No vulnerabilities found — nothing to remediate.")
                return None

            verify_cmd = self._get_verify_command(build_system, container, workspace)
            build_error = None

            for attempt in range(1, MAX_PATCH_ATTEMPTS + 1):
                if attempt > 1:
                    if self._is_java_compile_error(build_error):
                        # Build file upgrade is fine — only Java sources need more work.
                        # Keep pom.xml / build.gradle as patched; LLM sees the partially-fixed
                        # sources and can add what's still missing iteratively.
                        print(f"Retry {attempt}/{MAX_PATCH_ATTEMPTS}: Java compile errors — keeping build file, re-patching sources...")
                    else:
                        # Build file itself is broken (malformed XML, missing property, etc.).
                        # Restore it so the LLM starts from a clean slate.
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

    def _is_java_compile_error(self, build_error: str) -> bool:
        """True when all errors are in Java source files (not in the build file itself)."""
        import re
        has_java = bool(re.search(r'\S+\.java:\[?\d+', build_error))
        has_build_file_parse = any(k in build_error for k in (
            "Non-parseable POM", "ProjectBuildingException", "Invalid POM",
            "could not resolve", "dependency resolution"
        ))
        return has_java and not has_build_file_parse

    def _restore_build_files(self, container, workspace, build_system, build_file):
        """Restore the build file(s) to their original committed state before a retry."""
        container.exec_run(f"git checkout HEAD -- {build_file}", workdir=workspace)
        if build_system == "gradle":
            # Restore version catalog too if it exists
            container.exec_run(
                "git checkout HEAD -- gradle/libs.versions.toml 2>/dev/null || true",
                workdir=workspace
            )

    def _extract_build_error(self, raw_output: str) -> str:
        """Return only the actionable error lines from a build log, not download noise."""
        keywords = ("[ERROR]", "[FATAL]", "BUILD FAILURE", "COMPILATION ERROR",
                    "cannot find symbol", "error:", "package does not exist")
        lines = raw_output.splitlines()
        error_lines = [l for l in lines if any(k in l for k in keywords)]
        # Always include the last few lines as they usually contain the summary
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
        # Prefer the project's own Gradle wrapper so the version stays consistent
        if container.exec_run("test -f gradlew", workdir=workspace).exit_code == 0:
            return "./gradlew compileJava"
        return "gradle compileJava"

    def _scan_internal(self, container, workspace="/home/agent/workspace"):
        # OSV-Scanner exits 0 = clean, 1 = vulnerabilities found, >1 = error.
        # Use demux=True to keep stdout (JSON) separate from stderr (progress logs).
        scan = container.exec_run(
            "osv-scanner --format json .",
            workdir=workspace,
            demux=True
        )
        stdout, stderr = scan.output

        if scan.exit_code > 1:
            err_msg = stderr.decode("utf-8", errors="replace") if stderr else "(no stderr)"
            print(f"OSV-Scanner error (exit {scan.exit_code}): {err_msg[:300]}")
            return []

        if not stdout:
            print("OSV-Scanner produced no output.")
            return []

        raw = stdout.decode("utf-8", errors="replace").strip()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"Failed to parse OSV-Scanner JSON: {e}\nRaw output: {raw[:300]}")
            return []

        ghsa_ids = set()
        for result in data.get("results", []):
            for pkg in result.get("packages", []):
                for vuln in pkg.get("vulnerabilities", []):
                    vid = vuln.get("id", "")
                    if vid.startswith("GHSA-"):
                        ghsa_ids.add(vid)
                    # Collect GHSA aliases too (e.g., when primary ID is a CVE)
                    for alias in vuln.get("aliases", []):
                        if alias.startswith("GHSA-"):
                            ghsa_ids.add(alias)

        if ghsa_ids:
            print(f"Vulnerabilities found: {', '.join(sorted(ghsa_ids))}")
        else:
            print("OSV-Scanner found no GHSA vulnerabilities.")

        return sorted(ghsa_ids)
