import docker
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
            cves = self._scan_internal(container)
            if cves and actor.autonomous_patch(cves):
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

    def _scan_internal(self, container):
        container.exec_run("osv-scanner -j .", workdir="/home/agent/workspace")
        # TODO: parse OSV-Scanner JSON output; using known ID for now
        return ["GHSA-3mc7-4q67-5847"]
