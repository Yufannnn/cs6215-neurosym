# Feasibility report (Gates 0 and 1)

Date: 22 October 2026. Machine: Mac mini (Apple silicon, macOS), Python 3.14.0. Every result below was actually executed; nothing is inferred from documentation unless stated.

## Gate 0: scaffold audit

The existing scaffold is kept: centralized SoCLaaS client (`src/neurosym/llm.py`), `.env`, report skeleton (compiles with `acmart`), and design log.

Discrepancies with the plan, to resolve in Gate 2:

| Plan requirement | Current state | Action |
|---|---|---|
| Cache key includes replicate ID, prompt/schema/analysis versions | Key = hash of the request only | Add `replicate` and version fields to the key |
| Fresh-generation runs kept separate from the frozen response set | `cache=False` overwrites the same cache entry | Fresh runs write under a distinct replicate ID; never overwrite |
| Store raw response, parse status, returned identity, fingerprint | Raw response stored; served model logged; fingerprint and parse status not logged | Log `system_fingerprint` and parse status |
| Never call `default` in reported runs | `.env` has `SOCLAAS_MODEL="default"` | Pin model IDs in `configs/`; `default` only for the smoke test |
| Folders `analyzer/`, `prompts/`, `evaluation/`, `data/`, `configs/`, `tests/` | `src/neurosym/`, `src/neurosym/prompts/`, `eval/`; `subjects/` | Map `analyzer/` to `src/neurosym/`, `prompts/` to `src/neurosym/prompts/`, `evaluation/` to `eval/`. Renamed `subjects/` to `data/`; created `configs/` and `tests/` |

### SoCLaaS response format (measured)

| Model | Latency (trivial JSON request) | Served `model` | `system_fingerprint` | Notes |
|---|---|---|---|---|
| `qwen3-coder-next` | 0.27 s | `qwen3-coder-next` | `vllm-0.26.0-1cf708c9` | Valid JSON with `response_format=json_object`; no reasoning field |
| `qwen3.5:9b` | 2.31 s | `qwen3.5:9b` | `fp_ollama` | **Reasoning model.** With `max_tokens=60` it spent all tokens on hidden reasoning and returned empty content (`finish_reason=length`) |

`qwen3.5:9b` options tried on the same trivial request:

| Option | Latency | Output tokens | Content |
|---|---|---|---|
| `max_tokens=2000` | 10.5 s | 660 (about 2.9k characters of reasoning) | correct |
| `extra_body={"think": false}` | 4.0 s | 200, truncated | empty |
| `chat_template_kwargs.enable_thinking=false` | 3.9 s | 200, truncated | empty |
| `extra_body={"reasoning_effort": "none"}` | 1.1 s | 6 | correct |

Decision needed: run the small-model check with `reasoning_effort="none"` (same non-reasoning setting as the primary), or with reasoning and a larger output cap. Either way it is a recorded decoding setting. The fingerprint differs by backend (vLLM vs Ollama), so the model-size comparison also changes the serving stack.

These latencies are for a 20-token request and say nothing about analysis-sized requests.

## Gate 1: baseline and data

### Semgrep Community Edition

- Installed `semgrep==1.182.1` from PyPI into the project venv. It works on Python 3.14.
- Runs with `--metrics=off --disable-version-check`, no login, no Pro features.
- **JSON output has no dataflow traces, and `extra.lines` is the literal string `"requires login"`.** SARIF output with `--dataflow-traces` also has no `codeFlows`. The adapter therefore uses only rule ID, path, start/end line and column, and fingerprint, and re-reads the code span from the pinned file. All flow evidence comes from our own AST analysis; nothing from Semgrep traces.
- **Intraprocedural scope confirmed empirically.** With a draft taint rule (`flask.request.$ATTR` sources; `open()` path and `.exists()` receiver sinks) on hand-written fixtures:
  - direct request → `open()` flow: reported;
  - guard checks a normalized `candidate` but `open()` uses the original `name`: reported (correctly vulnerable);
  - request → `helper(x)` → `open(x)` in another function: **not reported**.
- On `BenchmarkTest00008` (official label: vulnerable; already design-exposed) the draft rule reported `p.exists()` on line 52.

### Community rules (semgrep/semgrep-rules @ `16b9e6d4`, 2026-10-21)

Python CWE-22 rules found: `python/flask/security/injection/path-traversal-open.yaml` and four Django rules (`path-traversal-open`, `path-traversal-join`, `path-traversal-file-name`, `request-data-fileresponse`). **The Flask rule is pattern-based, not taint mode, and only matches `open(...)`.** The benchmark mostly uses `pathlib` operators, `codecs.open`, `.exists()` and `.read_text()`, so the off-the-shelf rule cannot be the primary baseline without being uselessly weak.

Proposal: the primary baseline is a **project-authored, frozen Semgrep CE taint rule**, explicitly labelled as such. The community Flask rule is run unmodified as a reference row, so readers can see the off-the-shelf result.

### OWASP Benchmark for Python (@ `f1291485`, 2026-05-19, GPL-3.0)

Recomputed from `expectedresults-0.1.csv`: 1,230 cases in 14 categories. **`pathtraver`: 168 cases, 65 vulnerable, 103 safe.** (`cmdi`: 20 cases, 13 vulnerable.) This matches the published inventory.

Aggregate API inventory over the 168 path-traversal files (counts of files containing each pattern; no per-case labels were inspected):

| Pattern | Files |
|---|---|
| builtin `open(` | 77 |
| `pathlib.Path(` | 54 |
| `startswith` / `commonpath` checks | 29 |
| `.read_text()` / `.read_bytes()` | 28 |
| `codecs.open(` | 26 |
| `Path.open(` | 26 |
| `.exists()` | 26 |
| `os.path.exists(` | 11 |

Sources: `request.form` 54, `request.headers` 50, `request.query_string` 34, `request_wrapper` 24, `request.path` 23, `request.args` 23, `request.cookies` 10. No test file contains label-like comments.

**Helper-mediated flows.** Benchmark helpers (shared infrastructure, read in full) introduce cross-function behaviour that an intraprocedural engine cannot see:

- `helpers.separate_request.request_wrapper`: `get_form_parameter`, `get_query_parameter` and `get_cookie` return request data; **`get_safe_value` returns the constant `"bar"`**.
- `helpers.ThingFactory.createThing()` picks a class from a config file via `getattr`; both `doSomething(x)` implementations pass `x` through.
- `helpers.utils.get_parameter` / `get_parameter_list` return request args or form data.

Proposal: declare these as **versioned API contracts** in the frozen policy (sources, a non-source, and propagators). They are available equally to S, D, L, E and EC, so no arm gets hidden knowledge. They are derived from helper code, not from test cases or labels.

Exposure so far: `BenchmarkTest00008` (read in full). Aggregate regex counts over all 168 path-traversal files. No other test case was read.

### PyVul (@ `1172bfd1`, 2025-12-11)

- Commit-level dataset: 1,155 fix-commit URLs. CWE map: 1,952 entries. **CWE-22: 68 commits, 51 in the commit-level set, across 31 repositories** (django/django 12, mlflow/mlflow 7, ansible 2, gradio 2, streamlit 2; the rest have 1 each).
- Function-level dataset (JSON Lines): 2,173 records with `code_before`, `code_after`, `commit`, `commit_message`, `description`, `report_link`, `function_name`, `gpt_answer`. **104 CWE-22 function records.**
- `description`, `commit_message`, `report_link` and `gpt_answer` contain advisory and label information and must never enter model inputs.
- PyVul's own acquisition script (`benchmark_curation/data_collection/clone_checkout_commit.py`) was not run. We will write our own pinned fetch (clone, then check out the fix commit and its parent) and record rejected candidates.

Real-world selection (3 projects, 6–10 target pairs) is not done yet. `mlflow/mlflow` (7 commits) and `django/django` (12) are the obvious multi-commit candidates, but each case must first pass the plan's checks (advisory, vulnerable revision, actual fix, sink, local vs cross-function scope).

## Not needed

Java, a GPU, CodeQL and paid APIs are all unnecessary at this point.

## Open decisions for Yufan

1. Small-model decoding: `reasoning_effort="none"` or reasoning enabled (see above).
2. Primary baseline: project-authored frozen taint rule, plus the unmodified community rule as a reference row.
3. Benchmark helper contracts in the shared policy, as proposed above.
4. Real-world candidates: start screening from mlflow and django, plus one single-commit project with a local (intraprocedural) fix.
