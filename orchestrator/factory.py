import docker
import json
import os
from github import Github, Auth
from remediator import RemediationActor


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
            return

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
            print(f"Fork created at {fork.html_url}")

            auth_url = fork.clone_url.replace("https://", f"https://{self.gh_token}@")
            workspace = "/home/agent/workspace"

            container.exec_run(f"rm -rf {workspace}")
            container.exec_run(f"mkdir -p {workspace}")

            clone_res = container.exec_run(f"git clone {auth_url} {workspace}")
            if clone_res.exit_code != 0:
                print(f"Git Clone Failed: {clone_res.output.decode()}")
                return

            container.exec_run(f"git remote add upstream {upstream_url}", workdir=workspace)
            container.exec_run("git fetch upstream --tags", workdir=workspace)
            container.exec_run(f"git checkout {target_tag}", workdir=workspace)

            build_system, build_file = self._detect_build_system(container, workspace)
            if not build_system:
                print("Error: No supported build file found (pom.xml / build.gradle / build.gradle.kts)")
                return
            print(f"Detected build system: {build_system} ({build_file})")

            actor = RemediationActor(container, fork, build_system, build_file)
            cves = self._scan_internal(container, workspace)
            if not cves:
                print("No vulnerabilities found — nothing to remediate.")
                return

            if actor.autonomous_patch(cves):
                verify_cmd = self._get_verify_command(build_system, container, workspace)
                print(f"Verifying build with: {verify_cmd}")
                verify = container.exec_run(verify_cmd, workdir=workspace)
                if verify.exit_code == 0:
                    actor.create_pull_request(cves)
                else:
                    print(f"Build verification failed:\n{verify.output.decode()}")
        finally:
            container.stop()
            container.remove()

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
