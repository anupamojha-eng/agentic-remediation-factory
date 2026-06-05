"""
Sentinel self-improvement logger.

Every time Sentinel successfully patches a repo and opens a PR, this module
logs the input (build files + source files + CVEs) and output (patches) as a
training example. Over time this builds a ground-truth dataset of real patches
that were good enough to pass build verification.

Usage — add to remediator.py after a successful patch:
    from training.sentinel_logger import log_successful_patch
    log_successful_patch(ghsa_ids, files_input, patches_output, build_system, repo_url)

Or set SENTINEL_TRAINING_LOG env var to enable automatically.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

_SYSTEM_PROMPT = (
    "You are a Senior Security Engineer. "
    "Return ONLY a raw JSON object. "
    "No preamble, explanation, or markdown code blocks."
)

_DEFAULT_LOG = Path("training/data/sentinel_self.jsonl")


def log_successful_patch(
    ghsa_ids: list[str],
    files_input: dict[str, str],
    patches_output: dict[str, str],
    changes: list[str],
    build_system: str,
    repo_url: str,
    pr_url: str = "",
    log_path: Path | None = None,
):
    """
    Log a verified successful patch as a training example.
    Only called after build verification passes — these are confirmed correct.
    """
    log_path = log_path or Path(os.getenv("SENTINEL_TRAINING_LOG", str(_DEFAULT_LOG)))
    log_path.parent.mkdir(parents=True, exist_ok=True)

    files_section = "\n".join(
        f"\n### {fn}\n```\n{content}\n```" for fn, content in files_input.items()
    )

    prompt = f"""Fix the following security vulnerabilities in the provided build/source file(s).

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
}}"""

    answer = {
        "patches": patches_output,
        "changes": changes,
        "analysis": f"Security fix for {', '.join(ghsa_ids)} — build verified.",
    }

    example = {
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": json.dumps(answer)},
        ],
        "metadata": {
            "source": "sentinel_verified",
            "repo": repo_url,
            "pr_url": pr_url,
            "ghsa_ids": ghsa_ids,
            "build_system": build_system,
            "files_patched": list(patches_output.keys()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }

    with open(log_path, "a") as f:
        f.write(json.dumps(example) + "\n")

    print(f"  [training] Logged verified patch → {log_path}")
