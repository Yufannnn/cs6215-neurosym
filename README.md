# Evidence-Checked LLM Triage for Python Path-Traversal Warnings

Yufan (A0238993J) · CS6215 Advanced Topics in Program Analysis, NUS, Fall 2026

A comparative static-analysis study. A symbolic baseline (Semgrep CE taint analysis) reports possible CWE-22 path traversals in Python. Four refinement configurations then try to remove false warnings without discarding real vulnerabilities:

| Arm | What it is |
|---|---|
| **S** | Semgrep CE 1.182.1 with a project-authored, frozen taint rule (`baseline/rules/cwe22-taint.yaml`) |
| **D** | S, then our deterministic recognizers only (constant/overwrite, infeasible branch, sound containment) |
| **L** | S, then ordinary LLM triage of the enclosing function |
| **E** | S, then LLM triage over our structured evidence (definitions, branch feasibility, dominating guards) and four obligations |
| **EC** | E's *same* responses, then an evidence gate: a suppression stands only if its claim matches the extracted facts |

All arms consume the same baseline warnings, so no arm can exceed S's recall. The study measures the trade-off between **false-positive removal** and **true-positive retention**. Protocol: [`docs/protocol.md`](docs/protocol.md). Design iterations, including failed ones: [`docs/decisions.md`](docs/decisions.md).

## Layout

| Path | Contents |
|---|---|
| `baseline/rules/` | Frozen Semgrep rule (project-authored; mirrors the policy in `src/neurosym/evidence.py`) |
| `src/neurosym/evidence.py` | Deterministic intraprocedural evidence extractor (value analysis with constant folding, branch pruning, loop fixpoint, guard coverage) |
| `src/neurosym/refine.py` | Arm D recognizers and the EC evidence gate |
| `src/neurosym/triage.py`, `src/neurosym/prompts/` | Arms L and E: prompts (version `p2`), JSON validation, one schema-repair retry |
| `src/neurosym/llm.py` | SoCLaaS client: cached by request + replicate ID, every call logged |
| `src/neurosym/pipeline.py`, `cli.py` | Runs all arms on a subject set; refuses test data unless the `protocol-freeze` tag holds |
| `src/neurosym/scoring.py`, `tables.py`, `stability.py` | Metrics with family-cluster bootstrap; report tables; fresh-replicate stability |
| `data/owasp_split.csv` | Frozen family-grouped dev/test split of OWASP Benchmark for Python CWE-22 cases |
| `data/diagnostics/` | 36 paired programs (12 dev, 24 held-out), generator, manifest, mechanical label validation |
| `src/neurosym/realworld.py`, `data/realworld/` | PyVul CWE-22 screening, selected targets, file snapshots |
| `results/runs/<run>/` | Per run: raw Semgrep JSON, alerts, evidence records, per-arm decisions (with raw model output), scores, manifest |
| `results/llm_calls.jsonl` | One line per LLM call: served model, backend fingerprint, tokens, latency, cache hit, retries |
| `results/tables/`, `report/tables/` | Generated tables (Markdown / LaTeX) |
| `tests/` | 50 regression tests (offline; no API needed) |
| `report/` | ACM `sigconf` report source |

## Setup

Requirements: macOS or Linux, Python ≥ 3.11 (developed on 3.14.0), git, internet for the first fetch. No GPU or Java.

```bash
python3 -m venv .venv
.venv/bin/pip install -e . semgrep==1.182.1 pytest
# third-party subjects at the pinned revisions used in the report
mkdir -p data/downloads && cd data/downloads
git clone https://github.com/OWASP-Benchmark/BenchmarkPython && git -C BenchmarkPython checkout f1291485808b66e20ddb6b01b10dc71b3df8c8ba
git clone https://github.com/billquan/PyVul && git -C PyVul checkout 1172bfd1579b4ad2a524549412170d08ca618fb3
git clone https://github.com/semgrep/semgrep-rules && git -C semgrep-rules checkout 16b9e6d45f10649f6a531ec4838ed9924372c3bc
cd ../..
.venv/bin/python -m pytest -q tests           # 50 offline tests
```

LLM experiments use NUS SoCLaaS, an OpenAI-compatible API that is free for SoC users and needs the NUS network or VPN. Copy `.env.example` to `.env` and set `SOCLAAS_API_KEY`, then check access with `.venv/bin/python scripts/smoke_llm.py`.

## Reproducing the results

```bash
N=".venv/bin/python -m neurosym.cli"
$N run --subjects owasp:test --name test-owasp-qcn --model qwen3-coder-next --workers 2
$N run --subjects diag:test  --name test-diag-qcn  --model qwen3-coder-next --workers 2
$N run --subjects owasp:test --name test-owasp-q9b --model qwen3.5:9b --workers 2
$N run --subjects diag:test  --name test-diag-q9b  --model qwen3.5:9b --workers 2
.venv/bin/python -c "from neurosym import stability as s; print(s.summarize(s.run()))"
.venv/bin/python -c "from neurosym import realworld as r; r.screen(); r.materialize()"
$N run --subjects realworld:vulnerable --name rw-vulnerable --model qwen3-coder-next --workers 2
$N run --subjects realworld:fixed      --name rw-fixed      --model qwen3-coder-next --workers 2
.venv/bin/python scripts/realworld_eval.py
$N tables
cd report && latexmk -pdf -outdir=build main.tex
```

**Replay without API access.** If `results/llm_cache/` is present (it is not committed, but can be shared), add `--offline` to any `run`: stored responses are replayed and the API is never called. A cache miss is an error, not a silent network call. Without the cache, re-running calls the model again. The service models may have changed since 22 October 2026, so expect small differences. The frozen responses that produced the reported numbers are stored inside each `results/runs/<run>/decisions_{L,E}.jsonl`.

**Verified reproduction (2026-10-22).** A fresh clone of this repository on the same Mac (no `.env`, only the copied response cache) was set up exactly as above:
- all 50 tests passed;
- `--offline` replays of `test-diag-qcn` and `test-owasp-qcn` reproduced every per-arm decision and every score exactly, with 0 API calls;
- the report built (7 pages).

**Development runs**, used before the freeze and not reported as test results: `dev-offline-D`, `dev-smoke` (prompts p1), `dev-p2`, `dev-final-owasp`, `dev-final-diag`.

## Models

`qwen3-coder-next` (primary; vLLM backend, fingerprint `vllm-0.26.0-1cf708c9`) and `qwen3.5:9b` (small-model check; Ollama backend, `reasoning_effort="none"`). Temperature 0, JSON response format, 2,000 output tokens, at most 12,000 input tokens. See `configs/models.json`. The served model and fingerprint of every call are in `results/llm_calls.jsonl`.

## Licences of third-party subjects

OWASP Benchmark for Python is GPL-3.0; it is not redistributed here, only fetched at a pinned revision. PyVul and the real-world projects are fetched from their original repositories. The course handout is excluded from the repository.
