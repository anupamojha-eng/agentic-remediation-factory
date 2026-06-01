import os
import base64
from llm_client import SecurityAgentClient
from github import Github


class RemediationActor:
    def __init__(self, container, fork_object, build_system="maven", build_file="pom.xml"):
        self.container = container
        self.fork = fork_object
        self.build_system = build_system
        self.build_file = build_file
        self.llm = SecurityAgentClient()
        self.gh_token = os.getenv("GITHUB_TOKEN")
        self.workspace = "/home/agent/workspace"

    def get_build_files_content(self):
        """Returns {filename: content} for all build files relevant to patching."""
        files = {}

        result = self.container.exec_run(f"cat {self.build_file}", workdir=self.workspace)
        files[self.build_file] = result.output.decode()

        # For Gradle, also include the version catalog if present
        if self.build_system == "gradle":
            catalog = "gradle/libs.versions.toml"
            res = self.container.exec_run(f"cat {catalog}", workdir=self.workspace)
            if res.exit_code == 0:
                files[catalog] = res.output.decode()

        return files

    def autonomous_patch(self, ghsa_ids, build_error=None):
        files_content = self.get_build_files_content()
        plan = self.llm.get_remediation_plan(
            ghsa_ids, files_content, self.build_system, build_error
        )
        if not plan:
            return False

        patches = plan.get("patches", {})
        if not patches:
            print("LLM returned no patches")
            return False

        for change in plan.get("changes", []):
            print(f"  -> {change}")

        return all(self._write_file(fname, content) for fname, content in patches.items())

    def _write_file(self, filename, content):
        parent = os.path.dirname(filename)
        if parent:
            self.container.exec_run(f"mkdir -p {parent}", workdir=self.workspace)

        # Pass content via base64 to safely handle all special characters
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        python_code = f"import base64; open('{filename}', 'wb').write(base64.b64decode('{encoded}'))"
        res = self.container.exec_run(["python3", "-c", python_code], workdir=self.workspace)
        if res.exit_code != 0:
            print(f"Failed to write {filename}: {res.output.decode()}")
            return False
        print(f"Patched {filename}")
        return True

    def create_pull_request(self, ghsa_ids):
        new_branch = f"fix/{'-'.join(ghsa_ids)}"

        self.container.exec_run("git config --global user.email 'agent@sentinel.ai'", workdir=self.workspace)
        self.container.exec_run("git config --global user.name 'Sentinel Agent'", workdir=self.workspace)
        self.container.exec_run(f"git checkout -b {new_branch}", workdir=self.workspace)
        self.container.exec_run("git add .", workdir=self.workspace)
        self.container.exec_run(f"git commit -m 'Security: Automated fix for {ghsa_ids[0]}'", workdir=self.workspace)

        auth_url = self.fork.clone_url.replace("https://", f"https://{self.gh_token}@")
        self.container.exec_run(f"git push {auth_url} {new_branch} --force", workdir=self.workspace)

        parent_repo = self.fork.parent
        body = f"## Automated Security Remediation\nAddresses: {', '.join(ghsa_ids)}"

        try:
            pr = parent_repo.create_pull(
                title=f"Security: Fix {ghsa_ids[0]}",
                body=body,
                head=f"{self.fork.owner.login}:{new_branch}",
                base=parent_repo.default_branch
            )
            print(f"SUCCESS: PR Created at {pr.html_url}")
        except Exception as e:
            print(f"PR creation failed: {e}")
