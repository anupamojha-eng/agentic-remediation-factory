"""
Fine-tune sentinel-patcher on CVE patching data using Unsloth + QLoRA.

Runs anywhere with a GPU: Google Colab, Modal, RunPod, local CUDA.
Output: GGUF model uploaded to Hugging Face Hub.

Requirements (install before running):
    pip install "unsloth[colab-new]" trl transformers datasets huggingface_hub

Usage:
    # Local / Colab
    python training/train.py --data training/data/train.jsonl --push-to-hub

    # With explicit HF repo
    python training/train.py --data training/data/train.jsonl \
        --hf-repo anupamojha/sentinel-patcher-7b --push-to-hub

    # Dry run — train but don't push
    python training/train.py --data training/data/train.jsonl --no-push-to-hub
"""

import argparse
import json
import os
from pathlib import Path


# ── Config ────────────────────────────────────────────────────────────────────

BASE_MODEL      = "Qwen/Qwen2.5-Coder-7B-Instruct"
MAX_SEQ_LENGTH  = 8192     # covers most build file + source file prompts
LORA_RANK       = 16       # LoRA rank — higher = more capacity, more VRAM
LORA_ALPHA      = 16
BATCH_SIZE      = 2        # per-device batch size
GRAD_ACCUM      = 8        # effective batch = 2 * 8 = 16
LEARNING_RATE   = 2e-4
EPOCHS          = 3
WARMUP_RATIO    = 0.05
OUTPUT_DIR      = "training/output"
GGUF_QUANT      = "q4_k_m" # Q4_K_M: good quality/size tradeoff (~4GB for 7B)

DEFAULT_HF_REPO = "anupamojha/sentinel-patcher-7b"


def load_dataset(path: str):
    """Load JSONL training data and convert to HF Dataset."""
    from datasets import Dataset

    examples = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        ex = json.loads(line)
        examples.append({"messages": ex["messages"]})

    print(f"  Loaded {len(examples):,} training examples from {path}")
    return Dataset.from_list(examples)


def format_prompt(example, tokenizer):
    """Convert messages list to a single training string."""
    return tokenizer.apply_chat_template(
        example["messages"],
        tokenize=False,
        add_generation_prompt=False,
    )


def train(data_path: str, hf_repo: str, push_to_hub: bool):
    from unsloth import FastLanguageModel
    from trl import SFTTrainer, SFTConfig
    from transformers import TrainingArguments
    import torch

    print(f"\n{'='*60}")
    print(f"  Sentinel Patcher — Fine-tuning")
    print(f"  Base model:  {BASE_MODEL}")
    print(f"  Data:        {data_path}")
    print(f"  Output repo: {hf_repo}")
    print(f"{'='*60}\n")

    # ── Load base model with QLoRA (4-bit quantization) ──────────────────────
    print("Loading base model...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=BASE_MODEL,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=None,         # auto-detect: bfloat16 on Ampere+, float16 otherwise
        load_in_4bit=True,  # QLoRA — reduces VRAM ~4x
    )

    # Apply LoRA adapters — only these layers are trained
    model = FastLanguageModel.get_peft_model(
        model,
        r=LORA_RANK,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                         "gate_proj", "up_proj", "down_proj"],
        lora_alpha=LORA_ALPHA,
        lora_dropout=0,      # 0 is optimal for Unsloth
        bias="none",
        use_gradient_checkpointing="unsloth",  # saves VRAM
        random_state=42,
    )

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total     = sum(p.numel() for p in model.parameters())
    print(f"Trainable parameters: {trainable:,} / {total:,} ({100*trainable/total:.2f}%)")

    # ── Load and format dataset ───────────────────────────────────────────────
    print("\nPreparing dataset...")
    raw = load_dataset(data_path)

    # Format each example as a chat string
    dataset = raw.map(
        lambda ex: {"text": format_prompt(ex, tokenizer)},
        remove_columns=raw.column_names,
    )

    # ── Trainer ───────────────────────────────────────────────────────────────
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        args=SFTConfig(
            dataset_text_field="text",
            max_seq_length=MAX_SEQ_LENGTH,
            per_device_train_batch_size=BATCH_SIZE,
            gradient_accumulation_steps=GRAD_ACCUM,
            num_train_epochs=EPOCHS,
            warmup_ratio=WARMUP_RATIO,
            learning_rate=LEARNING_RATE,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=10,
            save_strategy="epoch",
            output_dir=OUTPUT_DIR,
            optim="adamw_8bit",
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            seed=42,
            report_to="none",   # set to "wandb" to enable W&B tracking
        ),
    )

    print("\nStarting training...")
    trainer_stats = trainer.train()

    print(f"\nTraining complete.")
    print(f"  Runtime:  {trainer_stats.metrics['train_runtime']:.0f}s")
    print(f"  Loss:     {trainer_stats.metrics['train_loss']:.4f}")

    # ── Export to GGUF ────────────────────────────────────────────────────────
    gguf_dir = Path(OUTPUT_DIR) / "gguf"
    gguf_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nExporting to GGUF ({GGUF_QUANT})...")
    model.save_pretrained_gguf(
        str(gguf_dir),
        tokenizer,
        quantization_method=GGUF_QUANT,
    )
    print(f"GGUF saved → {gguf_dir}")

    # ── Push to Hugging Face Hub ──────────────────────────────────────────────
    if push_to_hub:
        hf_token = os.getenv("HF_TOKEN")
        if not hf_token:
            print("\n⚠️  HF_TOKEN not set — skipping Hub push.")
            print("    Set HF_TOKEN and re-run with --push-to-hub to upload.")
        else:
            print(f"\nPushing to Hugging Face Hub: {hf_repo} ...")

            # Push LoRA adapter (small, ~100MB)
            model.push_to_hub(hf_repo, token=hf_token)
            tokenizer.push_to_hub(hf_repo, token=hf_token)

            # Push GGUF (for Ollama / llama.cpp users)
            model.push_to_hub_gguf(
                hf_repo,
                tokenizer,
                quantization_method=GGUF_QUANT,
                token=hf_token,
            )
            print(f"✅  Model live at: https://huggingface.co/{hf_repo}")
            print(f"    GGUF file available for Ollama:")
            print(f"    ollama pull hf.co/{hf_repo}")
    else:
        print(f"\nModel saved locally → {OUTPUT_DIR}")
        print("Run with --push-to-hub to upload to Hugging Face.")

    return str(gguf_dir)


def main():
    parser = argparse.ArgumentParser(description="Fine-tune sentinel-patcher")
    parser.add_argument("--data", default="training/data/train.jsonl",
                        help="Path to training JSONL file")
    parser.add_argument("--hf-repo", default=DEFAULT_HF_REPO,
                        help="Hugging Face repo to push model to")
    parser.add_argument("--push-to-hub", action="store_true", default=False,
                        help="Upload model to Hugging Face Hub after training")
    parser.add_argument("--no-push-to-hub", dest="push_to_hub",
                        action="store_false")
    args = parser.parse_args()

    train(
        data_path=args.data,
        hf_repo=args.hf_repo,
        push_to_hub=args.push_to_hub,
    )


if __name__ == "__main__":
    main()
