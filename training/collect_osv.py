"""
Collect training data from OSV vulnerability database dumps.

Downloads the full OSV data dump for Maven and PyPI, then generates
synthetic training pairs:
  input:  a build file pinned to a vulnerable version
  output: the same file patched to the minimum safe version

This produces high-volume, clean build-file patching training data
without needing real repos.

Usage:
    python training/collect_osv.py --ecosystems Maven PyPI --out training/data/osv.jsonl
    python training/collect_osv.py --ecosystems Maven --limit 500 --out training/data/osv_maven.jsonl
"""

import argparse
import io
import json
import zipfile
import re
import sys
from pathlib import Path

import requests

# OSV data dump URL pattern
_OSV_DUMP_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"

# System prompt used for all training examples — matches what Sentinel sends
_SYSTEM_PROMPT = (
    "You are a Senior Security Engineer. "
    "Return ONLY a raw JSON object. "
    "No preamble, explanation, or markdown code blocks."
)


def download_osv_dump(ecosystem: str) -> list[dict]:
    url = _OSV_DUMP_URL.format(ecosystem=ecosystem)
    print(f"  Downloading {ecosystem} dump from {url} ...")
    resp = requests.get(url, stream=True, timeout=120)
    resp.raise_for_status()

    vulns = []
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                data = json.loads(zf.read(name))
                vulns.append(data)
            except json.JSONDecodeError:
                continue
    print(f"  Loaded {len(vulns):,} {ecosystem} advisories.")
    return vulns


def _ghsa_ids(vuln: dict) -> list[str]:
    ids = [vuln.get("id", "")]
    ids += vuln.get("aliases", [])
    return [i for i in ids if i.startswith("GHSA-")]


def _fixed_version(affected_entry: dict) -> str | None:
    """Extract the earliest fixed version from an OSV affected entry."""
    for rng in affected_entry.get("ranges", []):
        for ev in rng.get("events", []):
            if "fixed" in ev:
                return ev["fixed"]
    # fallback: database_specific fix
    db = affected_entry.get("database_specific", {})
    return db.get("fixed") or db.get("last_known_affected_version_range")


def _last_affected_version(affected_entry: dict) -> str | None:
    """The highest version that is still vulnerable."""
    versions = affected_entry.get("versions", [])
    if versions:
        return versions[-1]
    for rng in affected_entry.get("ranges", []):
        last_introduced = None
        for ev in rng.get("events", []):
            if "introduced" in ev:
                last_introduced = ev["introduced"]
        if last_introduced and last_introduced != "0":
            return last_introduced
    return None


def _make_maven_pom(group: str, artifact: str, vuln_version: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
             http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>demo-app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>{group}</groupId>
            <artifactId>{artifact}</artifactId>
            <version>{vuln_version}</version>
        </dependency>
    </dependencies>
</project>"""


def _make_requirements_txt(package: str, vuln_version: str) -> str:
    return f"# Auto-generated for training\n{package}=={vuln_version}\nrequests>=2.28.0\n"


def _make_patched_maven_pom(group: str, artifact: str, fixed_version: str) -> str:
    return _make_maven_pom(group, artifact, fixed_version)


def _make_patched_requirements_txt(package: str, fixed_version: str) -> str:
    return f"# Auto-generated for training\n{package}>={fixed_version}\nrequests>=2.28.0\n"


def _build_prompt(ghsa_ids: list[str], build_system: str, files: dict[str, str]) -> str:
    files_section = "\n".join(
        f"\n### {fn}\n```\n{content}\n```" for fn, content in files.items()
    )
    return f"""Fix the following security vulnerabilities in the provided build/source file(s).

GHSAs to fix: {ghsa_ids}
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
}}

Rules:
- Each value in "patches" must be the COMPLETE file content with all fixes applied
- Only include files that actually need to be changed
- For pom.xml: update the <version> tag for the affected dependency
- For requirements.txt: update the version pin to the minimum safe version
- Preserve all formatting and file structure exactly"""


def _build_answer(filename: str, patched_content: str,
                  package: str, vuln_ver: str, fixed_ver: str,
                  ghsa_ids: list[str]) -> dict:
    return {
        "patches": {filename: patched_content},
        "changes": [f"Upgraded {package} from {vuln_ver} to {fixed_ver} to fix {', '.join(ghsa_ids)}"],
        "analysis": f"Updated {package} to {fixed_ver} which contains the fix for {', '.join(ghsa_ids)}.",
    }


def generate_maven_examples(vulns: list[dict], limit: int) -> list[dict]:
    examples = []
    for vuln in vulns:
        if len(examples) >= limit:
            break
        ghsas = _ghsa_ids(vuln)
        if not ghsas:
            continue
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("ecosystem") != "Maven":
                continue
            name = pkg.get("name", "")
            if ":" not in name:
                continue
            group, artifact = name.split(":", 1)
            fixed = _fixed_version(affected)
            vuln_ver = _last_affected_version(affected)
            if not fixed or not vuln_ver or fixed == "0":
                continue

            filename = "pom.xml"
            vuln_file = _make_maven_pom(group, artifact, vuln_ver)
            fixed_file = _make_patched_maven_pom(group, artifact, fixed)
            prompt = _build_prompt(ghsas, "maven", {filename: vuln_file})
            answer = _build_answer(filename, fixed_file, f"{group}:{artifact}", vuln_ver, fixed, ghsas)

            examples.append({
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": json.dumps(answer)},
                ],
                "metadata": {
                    "source": "osv_synthetic",
                    "ecosystem": "Maven",
                    "ghsa_ids": ghsas,
                    "package": f"{group}:{artifact}",
                    "vuln_version": vuln_ver,
                    "fixed_version": fixed,
                },
            })
    return examples


def generate_pypi_examples(vulns: list[dict], limit: int) -> list[dict]:
    examples = []
    for vuln in vulns:
        if len(examples) >= limit:
            break
        ghsas = _ghsa_ids(vuln)
        if not ghsas:
            continue
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("ecosystem") != "PyPI":
                continue
            package = pkg.get("name", "")
            if not package:
                continue
            fixed = _fixed_version(affected)
            vuln_ver = _last_affected_version(affected)
            if not fixed or not vuln_ver or fixed == "0":
                continue

            filename = "requirements.txt"
            vuln_file = _make_requirements_txt(package, vuln_ver)
            fixed_file = _make_patched_requirements_txt(package, fixed)
            prompt = _build_prompt(ghsas, "python", {filename: vuln_file})
            answer = _build_answer(filename, fixed_file, package, vuln_ver, fixed, ghsas)

            examples.append({
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": json.dumps(answer)},
                ],
                "metadata": {
                    "source": "osv_synthetic",
                    "ecosystem": "PyPI",
                    "ghsa_ids": ghsas,
                    "package": package,
                    "vuln_version": vuln_ver,
                    "fixed_version": fixed,
                },
            })
    return examples


def main():
    parser = argparse.ArgumentParser(description="Collect OSV training data")
    parser.add_argument("--ecosystems", nargs="+", default=["Maven", "PyPI"],
                        choices=["Maven", "PyPI"], help="Ecosystems to collect")
    parser.add_argument("--limit", type=int, default=2000,
                        help="Max examples per ecosystem")
    parser.add_argument("--out", default="training/data/osv.jsonl",
                        help="Output JSONL file path")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    all_examples = []
    for ecosystem in args.ecosystems:
        print(f"\n[{ecosystem}]")
        vulns = download_osv_dump(ecosystem)
        if ecosystem == "Maven":
            examples = generate_maven_examples(vulns, args.limit)
        else:
            examples = generate_pypi_examples(vulns, args.limit)
        print(f"  Generated {len(examples):,} training examples.")
        all_examples.extend(examples)

    with open(out_path, "w") as f:
        for ex in all_examples:
            f.write(json.dumps(ex) + "\n")

    print(f"\nWrote {len(all_examples):,} examples → {out_path}")
    print(f"Breakdown by ecosystem:")
    for eco in args.ecosystems:
        n = sum(1 for e in all_examples if e["metadata"]["ecosystem"] == eco)
        print(f"  {eco}: {n:,}")


if __name__ == "__main__":
    main()
