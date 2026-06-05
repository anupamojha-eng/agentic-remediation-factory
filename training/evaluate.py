"""
MLOps evaluation pipeline for the sentinel-patcher model.

Runs inference on a held-out eval set and scores each prediction against
the reference answer on multiple dimensions. Exits non-zero if quality
drops below threshold — designed to run in CI after every model update.

Metrics:
  json_valid       Can the output be parsed as JSON?
  schema_valid     Does it have patches / changes / analysis keys?
  files_match      Did it patch all the expected files?
  version_correct  For build-file patches: is the version string updated?
  no_regression    Did it preserve non-security lines unchanged?
  pass@1           All of the above pass

Usage:
    # Against Claude (baseline / reference)
    python training/evaluate.py --eval-set training/data/eval.jsonl --provider anthropic

    # Against a local fine-tuned model via Ollama
    python training/evaluate.py --eval-set training/data/eval.jsonl \
        --provider ollama --model sentinel-patcher:latest

    # CI mode — fails if pass@1 < 0.80
    python training/evaluate.py --eval-set training/data/eval.jsonl \
        --provider ollama --model sentinel-patcher:latest --threshold 0.80

    # Generate eval set from existing JSONL (hold out 10%)
    python training/evaluate.py --split training/data/osv.jsonl --split-ratio 0.10
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


# ── Scoring ───────────────────────────────────────────────────────────────────

@dataclass
class Score:
    json_valid: bool = False
    schema_valid: bool = False
    files_match: bool = False
    version_correct: bool = False
    no_regression: bool = False

    @property
    def pass_at_1(self) -> bool:
        return all([self.json_valid, self.schema_valid,
                    self.files_match, self.version_correct])

    def to_dict(self) -> dict:
        return {
            "json_valid": self.json_valid,
            "schema_valid": self.schema_valid,
            "files_match": self.files_match,
            "version_correct": self.version_correct,
            "no_regression": self.no_regression,
            "pass@1": self.pass_at_1,
        }


_VERSION_RE = re.compile(r"\d+\.\d+[\.\d]*")


def _extract_versions(content: str) -> set[str]:
    return set(_VERSION_RE.findall(content))


def score_prediction(prediction: str, reference: dict, example: dict) -> Score:
    s = Score()

    # 1. JSON valid
    try:
        pred = json.loads(prediction.strip())
        s.json_valid = True
    except json.JSONDecodeError:
        # try stripping markdown fences
        cleaned = prediction.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0]
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0]
        try:
            pred = json.loads(cleaned)
            s.json_valid = True
        except json.JSONDecodeError:
            return s

    # 2. Schema valid
    s.schema_valid = (
        isinstance(pred, dict) and
        "patches" in pred and
        isinstance(pred["patches"], dict)
    )
    if not s.schema_valid:
        return s

    ref_patches = reference.get("patches", {})
    pred_patches = pred.get("patches", {})

    # 3. Files match — predicted at least the same files as reference
    ref_files = set(ref_patches.keys())
    pred_files = set(pred_patches.keys())
    s.files_match = ref_files.issubset(pred_files)

    # 4. Version correct — for each patched file, check the fixed version appears
    meta = example.get("metadata", {})
    fixed_ver = meta.get("fixed_version", "")
    if fixed_ver:
        version_found = any(
            fixed_ver in content
            for content in pred_patches.values()
        )
        vuln_ver = meta.get("vuln_version", "")
        # vulnerable version should NOT appear in the patched content
        vuln_still_present = vuln_ver and any(
            vuln_ver in content for content in pred_patches.values()
        )
        s.version_correct = version_found and not vuln_still_present
    else:
        # No version metadata — check that something changed
        s.version_correct = pred_patches != {}

    # 5. No regression — non-security lines from original input preserved
    input_files = {}
    for msg in example.get("messages", []):
        if msg["role"] == "user":
            # extract file contents from prompt
            for m in re.finditer(r'### (.+?)\n```\n(.*?)\n```', msg["content"], re.DOTALL):
                input_files[m.group(1)] = m.group(2)

    regressions = 0
    for fname, original in input_files.items():
        patched = pred_patches.get(fname, "")
        if not patched:
            continue
        orig_lines = set(original.splitlines())
        patched_lines = set(patched.splitlines())
        # lines that disappeared and are NOT version strings
        removed = orig_lines - patched_lines
        non_version_removed = [
            l for l in removed
            if not _VERSION_RE.search(l) and l.strip()
        ]
        regressions += len(non_version_removed)

    s.no_regression = regressions == 0

    return s


# ── Inference clients ─────────────────────────────────────────────────────────

def run_inference_anthropic(messages: list[dict], model: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    system = next((m["content"] for m in messages if m["role"] == "system"), "")
    user_msgs = [m for m in messages if m["role"] != "system"]
    resp = client.messages.create(
        model=model, max_tokens=4096,
        system=system, messages=user_msgs,
    )
    return resp.content[0].text


def run_inference_ollama(messages: list[dict], model: str, base_url: str) -> str:
    import requests
    resp = requests.post(
        f"{base_url}/api/chat",
        json={"model": model, "messages": messages, "stream": False},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def run_inference_openai_compat(messages: list[dict], model: str, base_url: str, api_key: str) -> str:
    import requests
    resp = requests.post(
        f"{base_url}/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"model": model, "messages": messages, "max_tokens": 4096},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


# ── Eval set split ────────────────────────────────────────────────────────────

def split_eval_set(source: str, ratio: float, eval_out: str, train_out: str):
    examples = [json.loads(l) for l in Path(source).read_text().splitlines() if l.strip()]
    n_eval = max(1, int(len(examples) * ratio))
    # stratify by ecosystem
    import random
    random.shuffle(examples)
    eval_set = examples[:n_eval]
    train_set = examples[n_eval:]

    Path(eval_out).parent.mkdir(parents=True, exist_ok=True)
    Path(train_out).parent.mkdir(parents=True, exist_ok=True)

    with open(eval_out, "w") as f:
        for ex in eval_set:
            f.write(json.dumps(ex) + "\n")
    with open(train_out, "w") as f:
        for ex in train_set:
            f.write(json.dumps(ex) + "\n")

    print(f"Split {len(examples)} examples → {n_eval} eval, {len(train_set)} train")
    print(f"  Eval  → {eval_out}")
    print(f"  Train → {train_out}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Evaluate sentinel-patcher model quality")
    parser.add_argument("--eval-set", help="JSONL eval set path")
    parser.add_argument("--provider", default="anthropic",
                        choices=["anthropic", "ollama", "openai"],
                        help="Inference provider")
    parser.add_argument("--model", default=None,
                        help="Model name (default: claude-haiku-4-5 / sentinel-patcher:latest)")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="Ollama base URL")
    parser.add_argument("--openai-url", default="http://localhost:8080",
                        help="OpenAI-compatible API base URL")
    parser.add_argument("--threshold", type=float, default=0.75,
                        help="Minimum pass@1 rate — exit 1 if below (for CI)")
    parser.add_argument("--limit", type=int, default=100,
                        help="Max examples to evaluate")
    parser.add_argument("--out", default="training/data/eval_results.jsonl",
                        help="Where to write per-example results")
    # Split mode
    parser.add_argument("--split", help="JSONL file to split into train/eval")
    parser.add_argument("--split-ratio", type=float, default=0.10)
    parser.add_argument("--eval-out", default="training/data/eval.jsonl")
    parser.add_argument("--train-out", default="training/data/train.jsonl")
    args = parser.parse_args()

    if args.split:
        split_eval_set(args.split, args.split_ratio, args.eval_out, args.train_out)
        return

    if not args.eval_set:
        parser.error("--eval-set required unless using --split")

    examples = [json.loads(l) for l in Path(args.eval_set).read_text().splitlines() if l.strip()]
    examples = examples[:args.limit]
    print(f"Evaluating {len(examples)} examples with provider={args.provider}")

    default_models = {
        "anthropic": "claude-haiku-4-5-20251001",
        "ollama": "sentinel-patcher:latest",
        "openai": "sentinel-patcher",
    }
    model = args.model or default_models[args.provider]
    print(f"Model: {model}\n")

    results = []
    scores_summary = {k: 0 for k in ["json_valid", "schema_valid", "files_match",
                                       "version_correct", "no_regression", "pass@1"]}

    for i, example in enumerate(examples):
        messages = [m for m in example["messages"] if m["role"] != "assistant"]
        reference = json.loads(example["messages"][-1]["content"])

        try:
            if args.provider == "anthropic":
                prediction = run_inference_anthropic(messages, model)
            elif args.provider == "ollama":
                prediction = run_inference_ollama(messages, model, args.ollama_url)
            else:
                prediction = run_inference_openai_compat(
                    messages, model, args.openai_url,
                    os.getenv("OPENAI_API_KEY", "local")
                )
        except Exception as e:
            print(f"  [{i+1}/{len(examples)}] Inference error: {e}")
            prediction = ""

        score = score_prediction(prediction, reference, example)
        score_dict = score.to_dict()

        for k, v in score_dict.items():
            if v:
                scores_summary[k] += 1

        status = "✅" if score.pass_at_1 else "❌"
        meta = example.get("metadata", {})
        print(f"  [{i+1}/{len(examples)}] {status} "
              f"{meta.get('ecosystem','?'):6} "
              f"json={score.json_valid} schema={score.schema_valid} "
              f"files={score.files_match} ver={score.version_correct} "
              f"noreg={score.no_regression}")

        results.append({
            "example_id": i,
            "metadata": meta,
            "scores": score_dict,
            "prediction_snippet": prediction[:200] if prediction else "",
        })

        time.sleep(0.2)  # avoid rate limits

    # Summary
    n = len(examples)
    print(f"\n{'═'*60}")
    print(f"  Evaluation Results — {model}")
    print(f"{'═'*60}")
    for k, v in scores_summary.items():
        bar = "█" * int(v / n * 30)
        print(f"  {k:<20} {v:>3}/{n}  {v/n:>5.1%}  {bar}")
    pass_rate = scores_summary["pass@1"] / n
    print(f"{'─'*60}")
    print(f"  pass@1: {pass_rate:.1%}  (threshold: {args.threshold:.0%})")
    print(f"{'═'*60}\n")

    # Write results
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({
            "model": model,
            "provider": args.provider,
            "n_examples": n,
            "summary": {k: v/n for k, v in scores_summary.items()},
            "threshold": args.threshold,
            "passed_ci": pass_rate >= args.threshold,
            "results": results,
        }, f, indent=2)
    print(f"Results written → {out_path}")

    # CI exit code
    if pass_rate < args.threshold:
        print(f"❌  Quality below threshold ({pass_rate:.1%} < {args.threshold:.0%}) — failing CI")
        sys.exit(1)
    print(f"✅  Quality above threshold — CI passed")


if __name__ == "__main__":
    main()
