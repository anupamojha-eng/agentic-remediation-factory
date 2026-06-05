"""
Collect training data from real GitHub security fix PRs.

Searches GitHub for PRs that reference GHSA advisories and contain
changes to pom.xml, requirements.txt, or .java/.py source files.
Extracts before/after file content as source-patching training examples.

These are higher quality than OSV synthetic pairs because they show
real code transformations — especially for source file patching.

Usage:
    export GITHUB_TOKEN=ghp_...
    python training/collect_github.py --out training/data/github.jsonl --limit 300
    python training/collect_github.py --ecosystems python --out training/data/github_py.jsonl
"""

import argparse
import json
import os
import re
import time
from pathlib import Path

import requests

_GH_API = "https://api.github.com"
_SYSTEM_PROMPT = (
    "You are a Senior Security Engineer. "
    "Return ONLY a raw JSON object. "
    "No preamble, explanation, or markdown code blocks."
)

# Files we care about for training
_BUILD_FILES = {"pom.xml", "requirements.txt", "build.gradle", "pyproject.toml"}
_SOURCE_EXTS = {".java", ".py"}

# GHSA pattern in PR title/body
_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)


class GitHubClient:
    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def _get(self, url: str, params: dict = None) -> dict | list:
        while True:
            resp = self.session.get(url, params=params, timeout=30)
            if resp.status_code == 403 and "rate limit" in resp.text.lower():
                reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset - time.time() + 5, 10)
                print(f"  Rate limited — waiting {wait:.0f}s ...")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json()

    def search_security_prs(self, ecosystem: str, page: int = 1) -> list[dict]:
        if ecosystem == "maven":
            query = 'GHSA in:title,body pom.xml in:files is:pr is:merged'
        else:
            query = 'GHSA in:title,body requirements.txt in:files is:pr is:merged'

        data = self._get(f"{_GH_API}/search/issues", params={
            "q": query, "sort": "updated", "order": "desc",
            "per_page": 30, "page": page,
        })
        return data.get("items", [])

    def get_pr_files(self, owner: str, repo: str, pr_number: int) -> list[dict]:
        return self._get(f"{_GH_API}/repos/{owner}/{repo}/pulls/{pr_number}/files")

    def get_file_at_commit(self, owner: str, repo: str, path: str, ref: str) -> str | None:
        try:
            data = self._get(f"{_GH_API}/repos/{owner}/{repo}/contents/{path}",
                             params={"ref": ref})
            import base64
            if data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            return None

    def get_pr_detail(self, owner: str, repo: str, pr_number: int) -> dict:
        return self._get(f"{_GH_API}/repos/{owner}/{repo}/pulls/{pr_number}")


def extract_ghsa_ids(text: str) -> list[str]:
    return list(set(m.upper() for m in _GHSA_RE.findall(text or "")))


def process_pr(gh: GitHubClient, item: dict, ecosystem: str) -> list[dict]:
    """Extract before/after training pairs from a single security fix PR."""
    examples = []
    url_parts = item["pull_request"]["url"].split("/")
    owner, repo, pr_number = url_parts[-4], url_parts[-3], int(url_parts[-1])

    ghsas = extract_ghsa_ids(item.get("title", "") + " " + item.get("body", ""))
    if not ghsas:
        return []

    try:
        pr = gh.get_pr_detail(owner, repo, pr_number)
        base_sha = pr["base"]["sha"]
        head_sha = pr["head"]["sha"]
        files = gh.get_pr_files(owner, repo, pr_number)
    except Exception as e:
        print(f"    Skipping {owner}/{repo}#{pr_number}: {e}")
        return []

    relevant = [
        f for f in files
        if (Path(f["filename"]).name in _BUILD_FILES or
            Path(f["filename"]).suffix in _SOURCE_EXTS)
        and f.get("status") in ("modified", "changed")
    ]

    if not relevant:
        return []

    before_files, after_files = {}, {}
    for f in relevant:
        path = f["filename"]
        before = gh.get_file_at_commit(owner, repo, path, base_sha)
        after = gh.get_file_at_commit(owner, repo, path, head_sha)
        if before and after and before != after:
            before_files[path] = before
            after_files[path] = after

    if not before_files:
        return []

    build_system = "python" if ecosystem == "python" else "maven"
    files_section = "\n".join(
        f"\n### {fn}\n```\n{content}\n```" for fn, content in before_files.items()
    )
    prompt = f"""Fix the following security vulnerabilities in the provided build/source file(s).

GHSAs to fix: {ghsas}
Build system: {build_system}

Files to analyze and patch:
{files_section}

Return ONLY a JSON object in this exact format:
{{
    "patches": {{
        "<filename>": "<complete patched file content>"
    }},
    "changes": ["specific change descriptions"],
    "analysis": "brief explanation of fixes"
}}"""

    answer = {
        "patches": after_files,
        "changes": [f"Security fix for {', '.join(ghsas)} — see PR {owner}/{repo}#{pr_number}"],
        "analysis": f"Applied security fix from {owner}/{repo} PR #{pr_number}.",
    }

    examples.append({
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": json.dumps(answer)},
        ],
        "metadata": {
            "source": "github_pr",
            "ecosystem": ecosystem,
            "ghsa_ids": ghsas,
            "repo": f"{owner}/{repo}",
            "pr_number": pr_number,
            "files_patched": list(after_files.keys()),
        },
    })
    return examples


def main():
    parser = argparse.ArgumentParser(description="Collect GitHub security fix training data")
    parser.add_argument("--ecosystems", nargs="+", default=["maven", "python"],
                        choices=["maven", "python"])
    parser.add_argument("--limit", type=int, default=200,
                        help="Max examples per ecosystem")
    parser.add_argument("--out", default="training/data/github.jsonl")
    args = parser.parse_args()

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN not set.")
        raise SystemExit(1)

    gh = GitHubClient(token)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_examples = []
    for ecosystem in args.ecosystems:
        print(f"\n[{ecosystem}] Searching GitHub for security fix PRs...")
        page, collected = 1, 0
        while collected < args.limit:
            items = gh.search_security_prs(ecosystem, page)
            if not items:
                break
            for item in items:
                if collected >= args.limit:
                    break
                examples = process_pr(gh, item, ecosystem)
                if examples:
                    all_examples.extend(examples)
                    collected += len(examples)
                    print(f"  [{ecosystem}] {collected}/{args.limit} — "
                          f"{examples[0]['metadata']['repo']}#{examples[0]['metadata']['pr_number']} "
                          f"({len(examples[0]['metadata']['files_patched'])} files)")
                time.sleep(0.5)  # be kind to GitHub API
            page += 1

        print(f"  Collected {collected} examples from {ecosystem}.")

    with open(out_path, "w") as f:
        for ex in all_examples:
            f.write(json.dumps(ex) + "\n")

    print(f"\nWrote {len(all_examples):,} examples → {out_path}")


if __name__ == "__main__":
    main()
