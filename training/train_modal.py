"""
Modal wrapper for sentinel-patcher fine-tuning.

Spins up a cloud A100 on demand, runs training, uploads to HF Hub,
then tears down. You pay only for the GPU time (~$5-10 per run).

Setup:
    pip install modal
    modal setup          # authenticate with Modal
    export HF_TOKEN=hf_...
    export GITHUB_TOKEN=...

Usage:
    # Collect fresh data + train + push
    modal run training/train_modal.py

    # Train only (skip data collection)
    modal run training/train_modal.py --skip-collect

    # Dry run — train but don't push to HF Hub
    modal run training/train_modal.py --no-push
"""

import os
import modal
from pathlib import Path

# ── Modal app ─────────────────────────────────────────────────────────────────

app = modal.App("sentinel-patcher-training")

# Build the training image once — cached between runs
training_image = (
    modal.Image.debian_slim(python_version="3.11")
    # llama.cpp build deps — pre-installed so unsloth never hits the interactive prompt
    .apt_install("cmake", "curl", "git", "libcurl4-openssl-dev", "build-essential")
    .pip_install(
        "unsloth[colab-new]",
        "trl>=0.7.0",
        "transformers>=4.40.0",
        "datasets>=2.18.0",
        "huggingface_hub>=0.22.0",
        "requests",
        "torch",
        # Pre-install GGUF conversion deps so unsloth doesn't try `uv pip install` at runtime
        "gguf",
        "mistral_common",
        extra_index_url="https://download.pytorch.org/whl/cu121",
    )
    # Pre-build llama.cpp — unsloth looks for llama-quantize in the repo root, not build/bin/
    # Also install llama.cpp's own requirements.txt so convert_hf_to_gguf.py gets the
    # exact gguf package version it was written against.
    .run_commands(
        "git clone --depth=1 https://github.com/ggerganov/llama.cpp /root/llama.cpp"
        " && cd /root/llama.cpp && cmake -B build && cmake --build build --config Release -j$(nproc)"
        " && cp /root/llama.cpp/build/bin/llama-quantize /root/llama.cpp/llama-quantize"
        " && pip install -r /root/llama.cpp/requirements.txt"
        " && echo 'llama.cpp ready'"
    )
    .add_local_file(
        Path(__file__).parent / "train.py",
        remote_path="/root/training/train.py",
    )
    .add_local_file(
        Path(__file__).parent / "evaluate.py",
        remote_path="/root/training/evaluate.py",
    )
)

# Persistent volume for caching model weights between runs
# (avoids re-downloading 14GB base model every time)
model_cache = modal.Volume.from_name("sentinel-model-cache", create_if_missing=True)


# ── Training function (runs on cloud GPU) ─────────────────────────────────────

@app.function(
    image=training_image,
    gpu="A100",          # change to "T4" for cheaper (~$0.60/hr, slower)
    timeout=7200,        # 2 hour timeout
    volumes={"/model-cache": model_cache},
    secrets=[
        modal.Secret.from_name("hf-token"),       # HF_TOKEN
        modal.Secret.from_name("github-token"),   # GITHUB_TOKEN (for data collection)
    ],
)
def run_training(
    training_data: str,
    hf_repo: str = "anupamojha/sentinel-patcher-7b",
    push_to_hub: bool = True,
):
    """Fine-tune sentinel-patcher on A100. Called remotely by Modal."""
    import os
    import sys
    import json
    import tempfile
    from pathlib import Path

    # Write training data to a temp file inside the Modal container
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(training_data)
        data_path = f.name

    # Point HuggingFace cache at the persistent volume
    os.environ["HF_HOME"] = "/model-cache/hf"

    # llama.cpp was pre-built at /root/llama.cpp — unsloth looks in cwd
    os.chdir("/root")

    # Import and run training
    sys.path.insert(0, "/root")
    from training.train import train
    gguf_path = train(
        data_path=data_path,
        hf_repo=hf_repo,
        push_to_hub=push_to_hub,
    )

    return {"status": "success", "gguf_path": gguf_path, "hf_repo": hf_repo}


# ── Evaluation function ───────────────────────────────────────────────────────

@app.function(
    image=training_image,
    gpu="T4",            # T4 is enough for inference-only evaluation
    timeout=1800,
    secrets=[modal.Secret.from_name("hf-token")],
)
def run_evaluation(
    eval_data: str,
    hf_repo: str = "anupamojha/sentinel-patcher-7b",
    threshold: float = 0.75,
):
    """Run evaluate.py against the newly trained model via Ollama."""
    import subprocess
    import json
    import sys

    # Pull the model from HF Hub via Ollama
    subprocess.run(["ollama", "pull", f"hf.co/{hf_repo}"], check=True)

    sys.path.insert(0, "/root")
    from training.evaluate import run_inference_ollama, score_prediction

    examples = [json.loads(l) for l in eval_data.splitlines() if l.strip()]
    passed = 0
    for ex in examples:
        messages = [m for m in ex["messages"] if m["role"] != "assistant"]
        ref = json.loads(ex["messages"][-1]["content"])
        try:
            pred = run_inference_ollama(messages, f"hf.co/{hf_repo}", "http://localhost:11434")
            score = score_prediction(pred, ref, ex)
            if score.pass_at_1:
                passed += 1
        except Exception:
            pass

    pass_rate = passed / len(examples) if examples else 0
    return {
        "pass_rate": pass_rate,
        "passed_ci": pass_rate >= threshold,
        "n_examples": len(examples),
        "threshold": threshold,
    }


# ── Local entrypoint ──────────────────────────────────────────────────────────

@app.local_entrypoint()
def main(
    skip_collect: bool = False,
    no_push: bool = False,
    hf_repo: str = "anupamojha/sentinel-patcher-7b",
    threshold: float = 0.75,
):
    import json
    from pathlib import Path

    print("\n" + "="*60)
    print("  Sentinel Patcher — Modal Training Pipeline")
    print("="*60)

    # Step 1: Collect / use existing training data
    train_path = Path("training/data/train.jsonl")
    eval_path  = Path("training/data/eval.jsonl")

    import sys as _sys
    python = _sys.executable  # use the same python that launched this script

    Path("training/data").mkdir(parents=True, exist_ok=True)

    if not skip_collect or not train_path.exists():
        print("\n[1/4] Collecting training data...")
        os.system(
            f"{python} training/collect_osv.py --ecosystems Maven PyPI "
            "--limit 2000 --out training/data/osv_raw.jsonl"
        )
        os.system(
            f"{python} training/evaluate.py "
            "--split training/data/osv_raw.jsonl "
            "--split-ratio 0.10 "
            f"--eval-out {eval_path} "
            f"--train-out {train_path}"
        )
    else:
        print(f"\n[1/4] Using existing data: {train_path} ({sum(1 for _ in train_path.open())} examples)")

    training_data = train_path.read_text()
    eval_data     = eval_path.read_text() if eval_path.exists() else ""

    # Step 2: Train on Modal A100
    # .spawn() fires the function independently — safe to disconnect locally
    print(f"\n[2/4] Launching training on Modal A100 (detached)...")
    training_call = run_training.spawn(
        training_data=training_data,
        hf_repo=hf_repo,
        push_to_hub=not no_push,
    )
    print(f"  Training launched. Waiting for result (safe to Ctrl+C — job continues in cloud)...")
    result = training_call.get()
    print(f"  Training complete: {result}")

    if no_push:
        print("\n  --no-push set. Skipping evaluation and deployment.")
        return

    # Step 3: Evaluate the new model
    if eval_data:
        print(f"\n[3/4] Evaluating model quality...")
        eval_call = run_evaluation.spawn(
            eval_data=eval_data,
            hf_repo=hf_repo,
            threshold=threshold,
        )
        eval_result = eval_call.get()
        print(f"  pass@1: {eval_result['pass_rate']:.1%} "
              f"(threshold: {threshold:.0%}) — "
              f"{'✅ PASSED' if eval_result['passed_ci'] else '❌ FAILED'}")

        if not eval_result["passed_ci"]:
            print(f"\n❌  Model quality below threshold. "
                  f"Previous model remains active.")
            raise SystemExit(1)
    else:
        print("\n[3/4] No eval set found — skipping quality gate.")

    # Step 4: Done
    print(f"\n[4/4] Pipeline complete.")
    print(f"  Model: https://huggingface.co/{hf_repo}")
    print(f"  Pull:  ollama pull hf.co/{hf_repo}")
    print(f"\n  To use with Sentinel:")
    print(f"  SENTINEL_LOCAL_MODEL=hf.co/{hf_repo} sentinel fix-cve --repo ...")
