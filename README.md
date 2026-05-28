<h1 align="center">DeteCode</h1>

<p align="center">
  AI-assisted CLI vulnerability scanner for PHP and JavaScript source code.
</p>

<p align="center">
  <strong>Static rules</strong> + <strong>taint analysis</strong> + <strong>optional CodeBERT model</strong>
</p>

## Overview

DeteCode is a prototype command-line tool for detecting web exploitation vulnerabilities in PHP and JavaScript projects. It reports the affected file, line number, CWE, CVSS score, severity, code snippet, detection engine, and confidence score.

The scanner uses a hybrid design:

- `local-rules`: regex-based rules for direct vulnerable patterns.
- `local-taint`: lightweight static taint analysis from user input to dangerous sinks.
- `semgrep`: optional Semgrep integration with local fallback.
- `ai-semantic`: optional CodeBERT-based classifier loaded from a local model directory.

DeteCode is offline-first. It can run without the AI model, and the model is optional for semantic analysis experiments.

## Features

- Scan a single file or a full directory.
- Supports PHP and JavaScript source files.
- Detects common web vulnerabilities:
  - SQL Injection (`CWE-89`)
  - Cross-Site Scripting (`CWE-79`)
  - OS Command Injection (`CWE-78`)
  - Path Traversal (`CWE-22`)
  - Code Injection (`CWE-94`)
  - PHP File Inclusion (`CWE-98`)
  - Unrestricted File Upload (`CWE-434`)
  - Insecure Deserialization (`CWE-502`)
  - Server-Side Request Forgery (`CWE-918`)
  - Open Redirect (`CWE-601`)
- Output formats: table, JSON, and text.
- Optional severity and path filters.
- Optional CodeBERT model support.

## Installation

Clone the repository:

```powershell
git clone https://github.com/rizkidsaputra/detecode.git
cd detecode
```

Create and activate a virtual environment:

```powershell
python -m venv env
.\env\Scripts\activate
```

Install DeteCode:

```powershell
python -m pip install -e .
```

Install optional dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Basic Usage

Scan the included vulnerable samples:

```powershell
python -m detecode scan .\tests\samples --engine local --format table
```

Scan a PHP/JavaScript project:

```powershell
python -m detecode scan "D:\path\to\source" --engine local --format table
```

Export JSON:

```powershell
python -m detecode scan .\tests\samples --engine local --format json
```

Filter by severity:

```powershell
python -m detecode scan .\tests\samples --severity high
```

Exclude noisy paths:

```powershell
python -m detecode scan D:\DVWA\vulnerabilities --engine local --exclude-path help --exclude-path impossible.php --format table
```

## Using the AI Model

The model is not stored inside this GitHub repository because model weights are large. Download the optional fine-tuned CodeBERT model from Hugging Face:

```text
https://huggingface.co/dunguasli/detecode-model-v1
```

Place it locally like this:

```text
models/
  codebert-webvuln/
    config.json
    model.safetensors
    tokenizer.json
    tokenizer_config.json
    vocab.json
    merges.txt
    special_tokens_map.json
```

Then run DeteCode with the model:

```powershell
python -m detecode scan .\tests\samples --engine hybrid --model-path .\models\codebert-webvuln --format table
```

You can also use the AI engine only:

```powershell
python -m detecode scan .\tests\samples --engine ai --model-path .\models\codebert-webvuln --format table
```

For the most stable demo results, use:

```powershell
python -m detecode scan D:\DVWA\vulnerabilities --engine local --exclude-path help --exclude-path impossible.php --exclude-path view_source --exclude-path view_help --format table
```

## Training Your Own Model

Install training dependencies:

```powershell
python -m pip install datasets transformers torch scikit-learn accelerate
```

Train CodeBERT with CrossVul:

```powershell
python scripts/train_codebert_crossvul.py --dataset hitoshura25/crossvul --output-dir models/codebert-webvuln --max-samples 2500 --epochs 2
```

Train with a larger security dataset:

```powershell
python scripts/train_codebert_crossvul.py --dataset ayshajavd/code-security-vulnerability-dataset --output-dir models/codebert-webvuln --max-samples 6000 --epochs 2
```

Recommended datasets:

- `hitoshura25/crossvul`
- `ayshajavd/code-security-vulnerability-dataset`
- CVEfixes
- NIST SARD

## Architecture

```text
Source Code
  -> file parser
  -> local rules / local taint / Semgrep / optional CodeBERT
  -> aggregator and deduplicator
  -> CWE to CVSS mapper
  -> CLI report
```

## Notes on Accuracy

The CodeBERT model is an experimental AI layer. During DVWA testing, local rules and taint analysis produced the most stable results. The model is useful for demonstrating AI-assisted semantic analysis, but it should not be treated as the only source of truth.

The `confidence` value is the scanner confidence for an individual finding. It is not the global accuracy of the model.

## Testing

Run tests:

```powershell
python -m pytest tests
```

Minimal smoke test:

```powershell
python -m detecode scan .\tests\samples --engine local --format text
```

## License

This project is a study group prototype for cybersecurity and AI learning.
