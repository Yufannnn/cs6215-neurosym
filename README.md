# CS6215 Course Project: Symbolic vs Neuro-symbolic Static Analysis

Yufan (A0238993J) · CS6215 Advanced Topics in Program Analysis, NUS, Fall 2026

> **Status: scaffold.** The analysis task, baseline and subjects are being planned (`docs/plan/`). Sections marked TBD are filled in as the project is implemented.

This repository compares an existing symbolic static-analysis tool (the **baseline**) with a self-designed **neuro-symbolic analyzer** for the same task, on the same subjects. It contains everything needed to reproduce the reported results.

## Layout

| Path | Contents |
|---|---|
| `baseline/` | How the symbolic baseline is obtained, configured and run (TBD) |
| `src/neurosym/` | The neuro-symbolic analyzer; `llm.py` is the logged and cached SoCLaaS client |
| `src/neurosym/prompts/` | All prompts, versioned with the code |
| `subjects/` | Evaluation subjects and the scripts that fetch them (TBD) |
| `eval/` | Scoring and comparison scripts (TBD) |
| `results/raw/`, `results/processed/` | Tool outputs and the tables/figures in the report |
| `results/llm_calls.jsonl` | One line per LLM call: served model, tokens, latency (resource budget) |
| `report/` | ACM `sigconf` LaTeX source of the final report |
| `docs/plan/` | Project plan |
| `docs/decisions.md` | Design iterations, including abandoned attempts |
| `tools/` | Downloaded third-party tools (not committed; see `tools/README.md`) |

## Setup

Requirements: Python ≥ 3.11, and the baseline's runtime (TBD; Java 17 for most JVM-based analyzers).

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
cp .env.example .env        # then add your SoCLaaS key
.venv/bin/python scripts/smoke_llm.py
```

SoCLaaS keys come from the [SoCLaaS portal](https://soclaas-portal.comp.nus.edu.sg). The API needs the NUS network or NUS VPN.

## Reproducing the results

TBD: one command per stage (fetch subjects → run baseline → run analyzer → score → regenerate tables).

LLM responses are cached under `results/llm_cache/`, keyed by the exact request, so reruns with an unchanged configuration make no new API calls.

## Model and configuration

All experiments use SoCLaaS. The model that served each call is recorded in `results/llm_calls.jsonl`. The `default` alias resolved to `qwen3.6:35b` on 2026-10-22; reported runs pin a concrete model ID.
