import docker
import git
import json
import os
from pathlib import Path
from remediator import RemediationActor  # <--- CRITICAL IMPORT

class RemediationFactory:
    def __init__(self):
        self.client = docker.from_env()
        self.base_dir = Path(__file__).parent.parent
        self.image_tag = "cve-fixer-sandbox:latest"

    def build_sandbox(self):
        """Builds the Docker sandbox image."""
        print(f"🔨 Building sandbox from {self.base_dir / 'sandbox'}...")
        image, logs = self.client.images.build(
            path=str(self.base_dir / "sandbox"),
            tag=self.image_tag,
            rm=True
        )

    def scan_for_cves(self, container):
        """Runs OSV-Scanner and returns a list of CVE/GHSA IDs."""
        print("🔍 Scanning for vulnerabilities...")
        result = container.exec_run(
            "osv-scanner scan --format json -r /home/agent/workspace",
            workdir="/home/agent/workspace"
        )
        try:
            raw_output = result.output.decode().strip()
            json_start = raw_output.find('{')
            if json_start == -1: return []
            findings = json.loads(raw_output[json_start:])
            cve_list = []
            for result_item in findings.get('results', []):
                for package_group in result_item.get('packages', []):
                    for vuln in package_group.get('vulnerabilities', []):
                        cve_id = vuln.get('id')
                        if cve_id: cve_list.append(cve_id)
            cve_list = sorted(list(set(cve_list)))
            print(f"🚨 Found {len(cve_list)} vulnerabilities: {', '.join(cve_list)}")
            return cve_list
        except:
            return []

    def clone_and_fix(self, repo_url: str, target_tag: str):
        """Orchestrates the autonomous remediation loop."""
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        local_repo_path = (self.base_dir / "temp_repos" / repo_name).resolve()

        # 1. Setup local repo
        if not local_repo_path.exists():
            repo = git.Repo.clone_from(repo_url, local_repo_path)
        else:
            repo = git.Repo(local_repo_path)
        repo.git.checkout(target_tag)

        # 2. Start Sandbox
        container = self.client.containers.run(
            image=self.image_tag,
            command="/bin/bash",
            volumes={str(local_repo_path): {'bind': '/home/agent/workspace', 'mode': 'rw'}},
            detach=True,
            tty=True
        )

        try:
            cves = self.scan_for_cves(container)
            if not cves: return

            actor = RemediationActor(container)
            build_command = "mvn clean compile -DskipTests -Dmaven.compiler.source=17 -Dmaven.compiler.target=17"

            # STAGE 1: Initial Build / Env Fix
            print("🏗️ Running initial build check...")
            build_result = container.exec_run(build_command, workdir="/home/agent/workspace")
            if build_result.exit_code != 0:
                print("❌ Build failed. Patching environment...")
                actor.fix_java_version_conflict()
                build_result = container.exec_run(build_command, workdir="/home/agent/workspace")

            # STAGE 2: Autonomous Remediation Loop
            if build_result.exit_code == 0:
                max_retries = 3
                attempt = 0
                last_error = None
                
                while attempt < max_retries:
                    print(f"🤖 Agent Attempt {attempt + 1}/{max_retries}...")
                    
                    # 1. AI Decision
                    success = actor.autonomous_patch(cves, build_error=last_error)
                    if not success:
                        print("⚠️ AI could not provide a remediation plan. Retrying...")
                        attempt += 1
                        continue
                    
                    # 2. Verification
                    print("🧪 Verifying fix with build...")
                    verify = container.exec_run(build_command, workdir="/home/agent/workspace")
                    
                    if verify.exit_code == 0:
                        print("🎊 SUCCESS: Project is built, patched, and verified!")
                        actor.create_pull_request(local_repo_path, cves)
                        break
                    else:
                        attempt += 1
                        last_error = verify.output.decode()[-2000:]
                        print(f"⚠️ Attempt {attempt} failed. Sending error context to AI...")
            else:
                print("💀 Could not stabilize environment. Check logs.")

        finally:
            print(f"✅ Cleanup complete for {repo_name}.")
            container.stop()
            container.remove()

def main():
    factory = RemediationFactory()
    factory.build_sandbox()
    factory.clone_and_fix("https://github.com/anupamojha-eng/jackson-databind", "jackson-databind-2.13.0")

if __name__ == "__main__":
    main()