#!/usr/bin/env python3
"""
Build a local SQLite knowledge base of security patterns from Semgrep rules.

Usage:
    python scripts/build_knowledge_base.py [--output DIR]

The output is a file named sentinel-kb-YYYY-MM-DD.sqlite in the current
directory (or the directory given by --output).  The file is also symlinked /
copied to training/data/sentinel-kb.sqlite so the orchestrator can find it
without knowing today's date.
"""
from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys
from datetime import date
from typing import Optional

try:
    import requests as _requests
except ImportError:
    _requests = None  # type: ignore[assignment]

try:
    import yaml as _yaml  # pyyaml (optional)
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

# ---------------------------------------------------------------------------
# Hardcoded fallback patterns (kept in sync with llm_client.py)
# ---------------------------------------------------------------------------

_BUILTIN_JAVA: list[tuple[str, str, str]] = [
    ("new ObjectInputStream(",
     "CWE-502",
     "Java deserialization – deserializing untrusted data can lead to RCE"),
    ("Runtime.getRuntime().exec(",
     "CWE-78",
     "OS command injection via Runtime.exec()"),
    ("new ProcessBuilder(",
     "CWE-78",
     "OS command injection via ProcessBuilder"),
    ('MessageDigest.getInstance("MD5"',
     "CWE-328",
     "Use of weak MD5 hashing algorithm"),
    ('MessageDigest.getInstance("SHA-1"',
     "CWE-328",
     "Use of weak SHA-1 hashing algorithm"),
    ("new Random(",
     "CWE-330",
     "Insecure randomness – use SecureRandom instead"),
    ("DocumentBuilderFactory.newInstance(",
     "CWE-611",
     "XML External Entity (XXE) via DocumentBuilderFactory"),
    ("XMLInputFactory.newInstance(",
     "CWE-611",
     "XML External Entity (XXE) via XMLInputFactory"),
]

_BUILTIN_PYTHON: list[tuple[str, str, str]] = [
    ("yaml.load(",
     "CWE-502",
     "Unsafe YAML load – use yaml.safe_load() instead"),
    ("pickle.loads(",
     "CWE-502",
     "Unsafe pickle deserialization – deserializing untrusted data leads to RCE"),
    ("pickle.load(",
     "CWE-502",
     "Unsafe pickle deserialization – deserializing untrusted data leads to RCE"),
]

# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

_GITHUB_CONTENTS_URL = (
    "https://api.github.com/repos/semgrep/semgrep-rules/contents/{path}"
)
_SEMGREP_DIRS = [
    "java/lang/security",
    "python/lang/security",
]


def _github_headers() -> dict:
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    return {"Accept": "application/vnd.github+json"}


def _fetch_json(url: str, session) -> Optional[object]:
    try:
        resp = session.get(url, headers=_github_headers(), timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        print(f"  [warn] GET {url} failed: {exc}", file=sys.stderr)
        return None


def _list_yml_files(path: str, session) -> list[dict]:
    url = _GITHUB_CONTENTS_URL.format(path=path)
    entries = _fetch_json(url, session)
    if not isinstance(entries, list):
        return []
    files = []
    for entry in entries:
        if entry.get("type") == "file" and entry.get("name", "").endswith(".yml"):
            files.append(entry)
        elif entry.get("type") == "dir":
            # recurse one level
            files.extend(_list_yml_files(entry["path"], session))
    return files


def _download_text(url: str, session) -> Optional[str]:
    try:
        resp = session.get(url, headers=_github_headers(), timeout=30)
        resp.raise_for_status()
        return resp.text
    except Exception as exc:
        print(f"  [warn] download {url} failed: {exc}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# YAML parsing (with pyyaml fallback to regex)
# ---------------------------------------------------------------------------

def _parse_yaml(text: str) -> Optional[dict]:
    if _HAS_YAML:
        try:
            return _yaml.safe_load(text)
        except Exception:
            return None
    # Minimal regex-based fallback – covers simple key: value lines
    doc: dict = {}
    for line in text.splitlines():
        m = re.match(r'^(\w[\w-]*):\s*(.*)', line)
        if m:
            doc[m.group(1)] = m.group(2).strip()
    return doc if doc else None


def _extract_grep_strings(rule: dict) -> list[str]:
    """
    Extract simple grep-able strings from a Semgrep rule dict.

    Strategy:
    - 'pattern' values that contain '(' → take text up to and including '('
    - 'pattern-regex' values → use as-is
    - recurse into 'pattern-either' and 'patterns' lists
    """
    results: list[str] = []

    def _visit(obj):
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key == "pattern" and isinstance(val, str):
                    val = val.strip()
                    if "(" in val:
                        # keep up to and including the first '('
                        prefix = val[: val.index("(") + 1]
                        results.append(prefix)
                elif key == "pattern-regex" and isinstance(val, str):
                    results.append(val.strip())
                elif key in ("pattern-either", "patterns") and isinstance(val, list):
                    for item in val:
                        _visit(item)
                else:
                    _visit(val)
        elif isinstance(obj, list):
            for item in obj:
                _visit(item)

    _visit(rule)
    # deduplicate preserving order
    seen: set[str] = set()
    out: list[str] = []
    for s in results:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _language_from_path(path: str) -> str:
    if path.startswith("java/"):
        return "java"
    if path.startswith("python/"):
        return "python"
    return "unknown"


# ---------------------------------------------------------------------------
# Rule parsing
# ---------------------------------------------------------------------------

def _parse_rule_file(text: str, path: str) -> list[dict]:
    """Return a list of pattern row dicts from a Semgrep rule YAML."""
    doc = _parse_yaml(text)
    if not doc or "rules" not in doc:
        return []

    rows: list[dict] = []
    rules = doc["rules"]
    if not isinstance(rules, list):
        return []

    default_lang = _language_from_path(path)

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_id = rule.get("id", "")
        if not rule_id:
            continue

        # language
        langs = rule.get("languages", [])
        if isinstance(langs, list):
            lang = langs[0] if langs else default_lang
        else:
            lang = str(langs)
        # normalise java variants
        if lang in ("java",):
            lang = "java"
        elif lang in ("python", "python3", "python2"):
            lang = "python"

        severity = rule.get("severity", "WARNING")
        metadata = rule.get("metadata", {}) or {}
        cwe_raw = metadata.get("cwe", "")
        if isinstance(cwe_raw, list):
            cwe = ", ".join(str(c) for c in cwe_raw)
        else:
            cwe = str(cwe_raw)
        message = rule.get("message", "")
        if isinstance(message, str):
            message = message.strip()

        grep_strings = _extract_grep_strings(rule)
        if not grep_strings:
            continue

        for gs in grep_strings:
            rows.append({
                "id": f"{rule_id}::{gs}",
                "language": lang,
                "grep_string": gs,
                "severity": severity,
                "cwe": cwe,
                "description": message,
                "source": "semgrep",
            })

    return rows


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

_DDL_PATTERNS = """
CREATE TABLE IF NOT EXISTS patterns (
    id TEXT PRIMARY KEY,
    language TEXT NOT NULL,
    grep_string TEXT NOT NULL,
    severity TEXT DEFAULT 'WARNING',
    cwe TEXT DEFAULT '',
    description TEXT DEFAULT '',
    source TEXT DEFAULT 'semgrep'
);
"""

_DDL_METADATA = """
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _create_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute(_DDL_PATTERNS)
    conn.execute(_DDL_METADATA)
    conn.commit()
    return conn


def _upsert_pattern(conn: sqlite3.Connection, row: dict):
    conn.execute(
        """
        INSERT OR REPLACE INTO patterns (id, language, grep_string, severity, cwe, description, source)
        VALUES (:id, :language, :grep_string, :severity, :cwe, :description, :source)
        """,
        row,
    )


def _insert_builtin_patterns(conn: sqlite3.Connection):
    for gs, cwe, desc in _BUILTIN_JAVA:
        _upsert_pattern(conn, {
            "id": f"builtin::java::{gs}",
            "language": "java",
            "grep_string": gs,
            "severity": "ERROR",
            "cwe": cwe,
            "description": desc,
            "source": "builtin",
        })
    for gs, cwe, desc in _BUILTIN_PYTHON:
        _upsert_pattern(conn, {
            "id": f"builtin::python::{gs}",
            "language": "python",
            "grep_string": gs,
            "severity": "ERROR",
            "cwe": cwe,
            "description": desc,
            "source": "builtin",
        })
    conn.commit()


# ---------------------------------------------------------------------------
# Main build logic
# ---------------------------------------------------------------------------

def build(output_dir: str = ".") -> str:
    """Build the knowledge base and return the path to the SQLite file."""
    today = date.today().strftime("%Y-%m-%d")
    db_filename = f"sentinel-kb-{today}.sqlite"
    db_path = os.path.join(output_dir, db_filename)

    print(f"Building knowledge base → {db_path}")
    conn = _create_db(db_path)

    # Always insert builtins first (so they survive even if Semgrep fails)
    _insert_builtin_patterns(conn)

    # Attempt to fetch Semgrep rules
    if _requests is None:
        print("  [warn] requests not available – skipping Semgrep download", file=sys.stderr)
        semgrep_ok = False
    else:
        semgrep_ok = _download_semgrep_rules(conn)

    # Record metadata
    conn.execute(
        "INSERT OR REPLACE INTO metadata VALUES ('built_at', ?)", (today,)
    )
    conn.execute(
        "INSERT OR REPLACE INTO metadata VALUES ('semgrep_synced', ?)",
        ("1" if semgrep_ok else "0",),
    )
    conn.commit()

    # Summary
    java_count = conn.execute(
        "SELECT COUNT(*) FROM patterns WHERE language = 'java'"
    ).fetchone()[0]
    python_count = conn.execute(
        "SELECT COUNT(*) FROM patterns WHERE language = 'python'"
    ).fetchone()[0]
    conn.close()

    print(
        f"Built KB: {java_count} java patterns, {python_count} python patterns "
        f"→ {db_filename}"
    )
    return db_path


def _download_semgrep_rules(conn: sqlite3.Connection) -> bool:
    """Download and insert Semgrep rules. Returns True if at least some rules loaded."""
    session = _requests.Session()
    inserted = 0

    for dir_path in _SEMGREP_DIRS:
        print(f"  Fetching Semgrep rules: {dir_path} …")
        files = _list_yml_files(dir_path, session)
        print(f"    Found {len(files)} .yml files")
        for file_entry in files:
            download_url = file_entry.get("download_url")
            if not download_url:
                continue
            text = _download_text(download_url, session)
            if not text:
                continue
            rows = _parse_rule_file(text, file_entry.get("path", dir_path))
            for row in rows:
                try:
                    _upsert_pattern(conn, row)
                    inserted += 1
                except sqlite3.Error as exc:
                    print(f"  [warn] DB insert error: {exc}", file=sys.stderr)
        conn.commit()

    print(f"  Inserted {inserted} Semgrep-derived patterns")
    return inserted > 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Build Sentinel knowledge base from Semgrep rules")
    parser.add_argument(
        "--output",
        default=".",
        help="Directory where the .sqlite file will be written (default: current dir)",
    )
    parser.add_argument(
        "--copy-to",
        default=None,
        dest="copy_to",
        help="Also copy the finished DB to this path (e.g. training/data/sentinel-kb.sqlite)",
    )
    args = parser.parse_args()

    db_path = build(output_dir=args.output)

    # Optionally copy to a fixed location for the orchestrator
    copy_target = args.copy_to or os.path.join(
        os.path.dirname(__file__), "..", "training", "data", "sentinel-kb.sqlite"
    )
    copy_target = os.path.abspath(copy_target)
    if db_path != copy_target:
        import shutil
        os.makedirs(os.path.dirname(copy_target), exist_ok=True)
        shutil.copy2(db_path, copy_target)
        print(f"  Copied → {copy_target}")


if __name__ == "__main__":
    main()
