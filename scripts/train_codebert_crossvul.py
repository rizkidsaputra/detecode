"""Fine-tune CodeBERT for PHP/JavaScript vulnerability classification.

Recommended in Google Colab/GPU:
    pip install datasets transformers torch scikit-learn accelerate
    python scripts/train_codebert_crossvul.py --output-dir models/codebert-webvuln

The trained folder can be used by the CLI:
    python -m detecode scan tests/samples --engine ai --model-path models/codebert-webvuln
"""

from __future__ import annotations

import argparse
import inspect
from collections import Counter

TARGET_CWES = [
    "safe",
    "CWE-22",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-98",
    "CWE-200",
    "CWE-306",
    "CWE-352",
    "CWE-434",
    "CWE-502",
    "CWE-918",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fine-tune CodeBERT on PHP/JS vulnerability data.")
    parser.add_argument("--dataset", default="hitoshura25/crossvul", help="HuggingFace dataset name.")
    parser.add_argument("--model", default="microsoft/codebert-base", help="Base model.")
    parser.add_argument("--output-dir", default="models/codebert-webvuln", help="Where to save the trained model.")
    parser.add_argument("--max-samples", type=int, default=2500, help="Limit samples for a fast tubes demo training run.")
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-length", type=int, default=256)
    return parser.parse_args()


def normalize_language(value: str) -> str:
    value = (value or "").lower()
    if value in {"js", "javascript", "jsx", "node"}:
        return "javascript"
    if value in {"php", "phtml"}:
        return "php"
    return value


def normalize_cwe(value: str | None) -> str:
    cwe = (value or "").upper().strip()
    return cwe if cwe in TARGET_CWES else "safe"


def prepare_dataset(dataset_name: str, max_samples: int) -> tuple[DatasetDict, dict[str, int], dict[int, str]]:
    from datasets import DatasetDict, load_dataset

    raw = load_dataset(dataset_name)
    split_name = "train" if "train" in raw else next(iter(raw.keys()))
    data = raw[split_name]

    def keep_php_js(record: dict) -> bool:
        language = normalize_language(record.get("language") or record.get("language_dir") or "")
        return language in {"php", "javascript"}

    data = data.filter(keep_php_js)

    if "is_vulnerable" in data.column_names:
        def to_example(record: dict) -> dict:
            label = normalize_cwe(record.get("cwe_id")) if record.get("is_vulnerable") else "safe"
            return {"text": record.get("code") or "", "label_name": label}
    else:
        def to_example(record: dict) -> dict:
            return {"text": record.get("vulnerable_code") or record.get("code") or "", "label_name": normalize_cwe(record.get("cwe_id"))}

    data = data.map(to_example, remove_columns=data.column_names)
    data = data.filter(lambda row: bool(row["text"]) and len(row["text"]) > 20)

    counts = Counter(data["label_name"])
    labels = ["safe"] + sorted(label for label in counts if label != "safe")
    label2id = {label: idx for idx, label in enumerate(labels)}
    id2label = {idx: label for label, idx in label2id.items()}

    data = data.map(lambda row: {"label": label2id[row["label_name"]]})
    if max_samples and len(data) > max_samples:
        data = data.shuffle(seed=42).select(range(max_samples))

    split = data.train_test_split(test_size=0.2, seed=42)
    validation_test = split["test"].train_test_split(test_size=0.5, seed=42)
    prepared = DatasetDict(
        train=split["train"],
        validation=validation_test["train"],
        test=validation_test["test"],
    )
    return prepared, label2id, id2label


def compute_metrics(eval_prediction):
    import numpy as np
    from sklearn.metrics import accuracy_score, f1_score

    logits, labels = eval_prediction
    preds = np.argmax(logits, axis=-1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "macro_f1": f1_score(labels, preds, average="macro"),
    }


def make_training_args(training_args_cls, args: argparse.Namespace):
    base_kwargs = {
        "output_dir": args.output_dir,
        "save_strategy": "epoch",
        "learning_rate": 2e-5,
        "per_device_train_batch_size": args.batch_size,
        "per_device_eval_batch_size": args.batch_size,
        "num_train_epochs": args.epochs,
        "weight_decay": 0.01,
        "load_best_model_at_end": True,
        "metric_for_best_model": "macro_f1",
        "report_to": "none",
    }
    signature = inspect.signature(training_args_cls.__init__)
    if "eval_strategy" in signature.parameters:
        base_kwargs["eval_strategy"] = "epoch"
    else:
        base_kwargs["evaluation_strategy"] = "epoch"
    return training_args_cls(**base_kwargs)


def make_trainer(trainer_cls, **kwargs):
    signature = inspect.signature(trainer_cls.__init__)
    trainer_kwargs = {
        "model": kwargs["model"],
        "args": kwargs["args"],
        "train_dataset": kwargs["train_dataset"],
        "eval_dataset": kwargs["eval_dataset"],
        "data_collator": kwargs["data_collator"],
        "compute_metrics": kwargs["compute_metrics"],
    }
    if "tokenizer" in signature.parameters:
        trainer_kwargs["tokenizer"] = kwargs["tokenizer"]
    elif "processing_class" in signature.parameters:
        trainer_kwargs["processing_class"] = kwargs["tokenizer"]
    return trainer_cls(**trainer_kwargs)


def main() -> None:
    args = parse_args()

    try:
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            DataCollatorWithPadding,
            Trainer,
            TrainingArguments,
        )
    except ImportError as exc:
        raise SystemExit(
            "Dependency training belum terinstall. Jalankan: "
            "python -m pip install datasets transformers torch scikit-learn accelerate"
        ) from exc

    dataset, label2id, id2label = prepare_dataset(args.dataset, args.max_samples)

    tokenizer = AutoTokenizer.from_pretrained(args.model)

    def tokenize(batch: dict) -> dict:
        return tokenizer(batch["text"], truncation=True, max_length=args.max_length)

    tokenized = dataset.map(tokenize, batched=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model,
        num_labels=len(label2id),
        label2id=label2id,
        id2label=id2label,
    )

    training_args = make_training_args(TrainingArguments, args)

    trainer = make_trainer(
        Trainer,
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["validation"],
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics=compute_metrics,
    )
    trainer.train()
    print("Test metrics:", trainer.evaluate(tokenized["test"]))
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    print(f"Saved model to {args.output_dir}")


if __name__ == "__main__":
    main()
