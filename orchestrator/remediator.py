import os
import re
import sys
import base64
from llm_client import SecurityAgentClient
from github import Github

# Optional self-improvement logging — enabled when SENTINEL_TRAINING_LOG is set
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
try:
    from training.sentinel_logger import log_successful_patch as _log_patch
    _TRAINING_LOG = os.getenv("SENTINEL_TRAINING_LOG")
except ImportError:
    _log_patch = None
    _TRAINING_LOG = None

# Maximum source file size to include in LLM prompt (bytes)
MAX_SOURCE_FILE_BYTES = 30_000


class RemediationActor:
    def __init__(self, container, fork_object, build_system="maven", build_file="pom.xml"):
        self.container = container
        self.fork = fork_object
        self.build_system = build_system
        self.build_file = build_file
        self.llm = SecurityAgentClient()
        self.gh_token = os.getenv("GITHUB_TOKEN")
        self.workspace = "/home/agent/workspace"
        self.audit: dict = {"patterns_found": {}, "patches_written": [], "attempt": 1, "build_output": ""}

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

    def get_affected_java_files(self, build_error: str) -> dict:
        """
        Parse compile/runtime errors for absolute source file paths (.java or .py),
        read each file from the container, and return {relative_path: content}.
        Only includes files under MAX_SOURCE_FILE_BYTES to keep the LLM prompt tractable.
        """
        # Java: /workspace/.../Foo.java:[line,col]  — stop at ':' to drop line info
        # Python: File "/workspace/.../foo.py", line N  — stop at '"' to drop quote
        abs_paths = [
            m[0] for m in re.findall(
                rf'{re.escape(self.workspace)}(/[^\s:,"]+\.(java|py))', build_error
            )
        ]
        files = {}
        for rel_path in dict.fromkeys(abs_paths):   # deduplicate, preserve order
            abs_path = self.workspace + rel_path
            res = self.container.exec_run(f"cat {abs_path}")
            if res.exit_code != 0:
                continue
            content = res.output.decode("utf-8", errors="replace")
            if len(content.encode()) > MAX_SOURCE_FILE_BYTES:
                print(f"  Skipping {rel_path} (>{MAX_SOURCE_FILE_BYTES} bytes)")
                continue
            files[rel_path.lstrip("/")] = content
            print(f"  Including source file: {rel_path.lstrip('/')}")
        return files

    def get_vulnerable_code_files(self, ghsa_ids: list) -> dict:
        """
        Ask the LLM which Java code patterns make these CVEs exploitable, then
        grep the source tree for those patterns and return matching file contents.
        This catches insecure usage of vulnerable libraries (transitive or direct).
        """
        patterns = self.llm.get_vulnerable_patterns(ghsa_ids, self.build_system)
        if not patterns:
            return {}

        # Source file extension depends on the language
        src_ext = "*.py" if self.build_system == "python" else "*.java"
        print(f"  Scanning source tree for exploitable patterns: {patterns}")
        MAX_SOURCE_FILES = 10
        files = {}
        for pattern in patterns:  # priority-ordered: _PYTHON_ALWAYS_CHECK first
            if len(files) >= MAX_SOURCE_FILES:
                break
            # Use list form so Docker exec runs grep directly (no shell needed)
            result = self.container.exec_run(
                ["grep", "-rl", f"--include={src_ext}", pattern, "."],
                workdir=self.workspace
            )
            if result.exit_code == 0:
                for path in result.output.decode().splitlines():
                    path = path.strip()
                    if not path or path in files:
                        continue
                    res = self.container.exec_run(f"cat {path}", workdir=self.workspace)
                    if res.exit_code != 0:
                        continue
                    content = res.output.decode("utf-8", errors="replace")
                    if len(content.encode()) <= MAX_SOURCE_FILE_BYTES:
                        files[path] = content
                        print(f"  Found vulnerable pattern '{pattern}' in: {path}")
                        self.audit["patterns_found"].setdefault(pattern, []).append(path)
        return files

    def autonomous_patch(self, ghsa_ids, build_error=None):
        files_content = self.get_build_files_content()

        if build_error:
            # Retry pass: include Java files that the compiler complained about
            java_files = self.get_affected_java_files(build_error)
            if java_files:
                print(f"  Feeding {len(java_files)} Java source file(s) to LLM for co-patching.")
                files_content.update(java_files)
        else:
            # First pass: proactively search for exploitable code patterns
            vuln_files = self.get_vulnerable_code_files(ghsa_ids)
            if vuln_files:
                print(f"  Including {len(vuln_files)} file(s) with exploitable patterns.")
                files_content.update(vuln_files)

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

        # Validate patches before writing — catch malformed XML/TOML early
        for fname, content in patches.items():
            err = self._validate_patch(fname, content)
            if err:
                print(f"  Patch for {fname} is invalid ({err}) — aborting this attempt.")
                return False

        success = all(self._write_file(fname, content) for fname, content in patches.items())

        # Self-improvement: log verified patches for future fine-tuning
        if success and _TRAINING_LOG and _log_patch:
            try:
                _log_patch(
                    ghsa_ids=ghsa_ids,
                    files_input=files_content,
                    patches_output=patches,
                    changes=plan.get("changes", []),
                    build_system=self.build_system,
                    repo_url=self.fork.parent.html_url if self.fork.parent else self.fork.html_url,
                )
            except Exception:
                pass  # never let logging break the main flow

        return success

    def _validate_patch(self, filename: str, content: str) -> str:
        """Return an error string if the patch content is structurally invalid, else ''."""
        if filename.endswith(".xml"):
            try:
                import xml.etree.ElementTree as ET
                ET.fromstring(content)
            except Exception as e:
                return f"invalid XML: {e}"
        elif filename.endswith(".toml"):
            try:
                import tomllib  # Python 3.11+
                tomllib.loads(content)
            except ImportError:
                pass  # older Python — skip validation
            except Exception as e:
                return f"invalid TOML: {e}"
        return ""

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
        if filename not in self.audit["patches_written"]:
            self.audit["patches_written"].append(filename)
        return True

    def create_pull_request(self, ghsa_ids):
        from datetime import datetime
        ts = datetime.utcnow().strftime("%m%d-%H%M")
        if len(ghsa_ids) == 1:
            new_branch = f"fix/{ghsa_ids[0]}-{ts}"
        else:
            new_branch = f"fix/{ghsa_ids[0]}-and-{len(ghsa_ids) - 1}-more-{ts}"

        self.container.exec_run("git config --global user.email 'agent@sentinel.ai'", workdir=self.workspace)
        self.container.exec_run("git config --global user.name 'Sentinel Agent'", workdir=self.workspace)
        self.container.exec_run(f"git checkout -b {new_branch}", workdir=self.workspace)
        self.container.exec_run("git add .", workdir=self.workspace)
        self.container.exec_run(f"git commit -m 'Security: Automated fix for {ghsa_ids[0]}'", workdir=self.workspace)

        auth_url = self.fork.clone_url.replace("https://", f"https://{self.gh_token}@")
        push = self.container.exec_run(f"git push {auth_url} {new_branch} --force", workdir=self.workspace)
        if push.exit_code != 0:
            print(f"Push failed: {push.output.decode()}")
            return self._patch_fallback(ghsa_ids, new_branch)

        parent_repo = self.fork.parent if self.fork.parent else self.fork
        body = self._build_pr_body(ghsa_ids)

        try:
            pr = parent_repo.create_pull(
                title=f"Security: Fix {len(ghsa_ids)} vulnerabilit{'y' if len(ghsa_ids) == 1 else 'ies'} ({ghsa_ids[0]}{'...' if len(ghsa_ids) > 1 else ''})",
                body=body,
                head=f"{self.fork.owner.login}:{new_branch}",
                base=parent_repo.default_branch,
            )
            print(f"SUCCESS: PR Created at {pr.html_url}")
            return pr.html_url
        except Exception as e:
            print(f"PR creation failed: {e}")
            return self._patch_fallback(ghsa_ids, new_branch)

    def _build_pr_body(self, ghsa_ids: list) -> str:
        from datetime import datetime
        a = self.audit
        ghsa_badges = " ".join(f"`{g}`" for g in ghsa_ids)

        # Source changes table
        if a["patches_written"]:
            changes_rows = "\n".join(
                f"| `{f}` | {', '.join(f'`{p}`' for p, files in a['patterns_found'].items() if f in files) or 'dependency update'} |"
                for f in a["patches_written"]
            )
            changes_table = f"| File | Change |\n|------|--------|\n{changes_rows}"
        else:
            changes_table = "_No source files patched — dependency version update only._"

        # Build output (truncated)
        build_out = (a["build_output"] or "").strip()
        build_snippet = "\n".join(build_out.splitlines()[-30:]) if build_out else "(no output captured)"

        lang = "Python 3 + pip" if self.build_system == "python" else f"JDK 17 + {'Maven' if self.build_system == 'maven' else 'Gradle'}"
        attempt_str = f"{a['attempt']} / 3"
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        return f"""\
## Automated Security Remediation

This PR was generated by [Sentinel](https://github.com/anupamojha-eng/agentic-remediation-factory), \
an autonomous security remediation agent.

---

### CVEs Addressed
{ghsa_badges}

### Files Changed
{changes_table}

### Build Verification
- **Status:** ✅ Passed
- **Attempts:** {attempt_str}
- **Sandbox:** {lang}, isolated Docker container

<details>
<summary>Build output</summary>

```
{build_snippet}
```

</details>

---
*Generated by Sentinel at {ts}*"""

    def _patch_fallback(self, ghsa_ids: list, branch: str) -> str:
        """
        When the PR cannot be opened (push failed, GitHub API error, rate limit),
        extract the diff from the container and save it locally so the fix is not lost.
        """
        from datetime import datetime
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        diff_res = self.container.exec_run(
            ["bash", "-c", "git diff HEAD~1 HEAD"],
            workdir=self.workspace,
        )
        filename = f"sentinel-patch-{ts}.diff"
        if diff_res.exit_code == 0 and diff_res.output:
            with open(filename, "wb") as fh:
                fh.write(diff_res.output)
            print(f"\n⚠️  PR could not be opened. Patch saved locally: {filename}")
            print(f"   To apply:  git apply {filename}")
            print(f"   To review: cat {filename}")
        else:
            print("\n⚠️  PR could not be opened and diff extraction failed.")
            print(f"   Branch '{branch}' may be partially pushed to your fork.")
        return None
