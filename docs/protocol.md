# Experimental protocol

Frozen before any test-split result is observed. Changes after the freeze are versioned corrections recorded in `docs/decisions.md`, and every affected arm is rerun. The plan this protocol implements is `docs/plan/PLAN.md`.

## Task and scope

Python CWE-22 path traversal, POSIX path semantics. A **warning** is a Semgrep CE taint finding whose sink is a filesystem path argument. The refinement arms may only keep or drop baseline warnings (`R ⊆ A`), so no arm can exceed the baseline's recall.

The threat model covers attacker-controlled Flask request data (`request.args/form/values/headers/cookies/query_string/path/data/files/json`, `get_json()`) and the benchmark helpers declared in the policy. Symlinks, races and Windows paths are out of scope. The analysis is intraprocedural: one function containing the sink.

## Shared policy (`configs/policy.yaml`)

Sources, sinks, sanitizers and API contracts are declared once and used by both the Semgrep rule and our evidence extractor:

- **Sinks:** builtin/`io`/`codecs`/`os` open; `pathlib.Path` file methods (`open`, `read_text`, `read_bytes`, `write_text`, `write_bytes`, `exists`, `is_file`, `is_dir`, `stat`, `unlink`, `iterdir`, `touch`, `mkdir`, `rmdir`); `os.path.exists/isfile/isdir/getsize/getmtime`; `os.remove/unlink/listdir/stat/scandir/rmdir/mkdir/makedirs`; `shutil` copy/move/rmtree; Flask `send_file` (path) and `send_from_directory` (directory argument only).
- **Sanitizers:** `werkzeug.utils.secure_filename`.
- **Benchmark helper contracts**, derived from helper source and not from tests:
  - `request_wrapper.get_form_parameter`, `get_query_parameter` and `get_cookie` are sources; `get_safe_value` returns a constant.
  - `helpers.utils.get_parameter` and `get_parameter_list` are sources.
  - `ThingFactory...doSomething(x)` propagates `x`.

The Semgrep rule is developed only on the development split and our development fixtures, then frozen with its SHA-256 and the Semgrep version.

## Arms

All arms consume the same frozen baseline warnings.

| ID | Definition |
|---|---|
| S | Semgrep CE 1.182.1, frozen rule `baseline/rules/cwe22-taint.yaml`, `--metrics=off` |
| D | S, then drop a warning only if a closed-set deterministic recognizer proves it: (1) every reaching definition of the sink value is a constant (provable overwrite); (2) every tainted reaching definition lies on a provably infeasible branch (constant-folded condition); (3) a documented safe API applies with its preconditions met; (4) sound containment: the sink value is the `realpath`/`abspath`+`normpath` (or `Path.resolve()`) of a join with a trusted constant root, and a dominating guard on that same value checks `startswith(root + os.sep)`, `commonpath([root, v]) == root` or `is_relative_to(root)`, with the rejecting branch exiting |
| L | S, then LLM triage on the raw enclosing-function source (same function text as E), ordinary prompt, JSON verdict |
| E | S, then LLM triage on our structured `EvidenceRecord` plus the four obligations (control, flow, confinement, coverage), JSON verdict with node IDs |
| EC | Same E responses (replayed, not regenerated), plus the evidence gate: suppress only if E proposes `suppress` and the gate passes |

**EC gate.** It checks schema validity, that cited node IDs exist in the record, and the record's file hash. Then, by reason kind:

- **constant/overwrite and unreachable-flow:** the corresponding extracted facts hold, and the evidence is complete for that claim.
- **guarded confinement:** the cited guard exists and dominates the sink with the polarity required to reach it, constrains the same reaching definition as the value consumed at the sink with no redefinition in between, and every incoming tainted definition is covered. If the guard predicate matches a D containment recognizer, the result is `trusted`. Otherwise it is `semantic_judgment_remaining` and suppression is allowed only when the model's confinement obligation cites that guard. These cases are reported separately.
- **trusted safe API:** the contract and its preconditions match.
- **unresolved:** never suppresses.

Malformed output, timeouts, or evidence flagged incomplete for the claim all retain the warning.

D and EC share the extractor. D gets no recognizer that EC's gate lacks, and vice versa. Neither is extended after any test result is seen.

## Subjects

1. **OWASP Benchmark for Python** @ `f1291485`, `pathtraver` category (168 cases; 65 vulnerable, 103 safe).
   - **Families:** hash of the normalized flow segment of the POST handler, from after the last `param` definition to the last `bar` definition, with literals and test IDs abstracted. 68 families.
   - **Split:** seeded (seed 6215) greedy family split. The family of the design-exposed `BenchmarkTest00008` goes to development first; then whole shuffled families are added until there are about 30 development cases. Everything else is test. The split is written to `data/owasp_split.csv` and never changed.
   - Scoring unit: the test case. A case is reported if any warning inside its file remains.
2. **Diagnostic pairs.** Development (12 pairs) and held-out (24 pairs) sets are written separately, from independent reference patterns (Python `os.path` and `pathlib` docs, Flask `send_from_directory` docs, OWASP Path Traversal guidance).
   - Each program's label is validated mechanically. A harness runs the handler with stubbed filesystem calls and attack payloads (`../`, absolute paths, encoded and nested variants), and checks whether any recorded path escapes the root. Programs whose validated behaviour disagrees with the intended label are fixed or dropped before freezing.
   - Unit: the program. Pair accuracy requires both members correct.
3. **Real-world (PyVul @ `1172bfd1`).** Up to 3 projects and 6–10 CWE-22 vulnerable/fixed target pairs.
   - Candidates are screened in a deterministic order (commit-level set, CWE-22, Python files changed, accessible revision) on feasibility only, and rejected candidates are recorded with reasons.
   - S runs on the files changed by the fix at the parent and fix revisions. Baseline coverage of every target is reported. Filter retention is evaluated only where S reports the target.
   - Other warnings are unlabeled. A fixed target is a negative only for that defect.

## Metrics

For a unit set with gold positives G, baseline-reported A and retained R:

- precision = |R∩G|/|R|
- recall = |R∩G|/|G|
- F1
- TP retention = |R∩G|/|A∩G|
- FP removal = |(A∖R)∖G|/|A∖G|
- wrongful suppressions = |(A∖R)∩G|
- raw TP/FP/FN/TN, abstention rate, invalid-output rate, coverage and failure counts

A zero denominator gives N/A. The scorer tests `recall = baseline recall × TP retention`.

Uncertainty: 95% cluster bootstrap over families (OWASP) or pairs (diagnostics), 2,000 resamples, seed 6215. Paired arm differences are bootstrapped on the same resamples. Real-world results are case counts only.

## Models and budget

Primary model: `qwen3-coder-next`. Small-model check: `qwen3.5:9b` with `reasoning_effort="none"` (non-thinking, verified on 22 Oct to disable reasoning).

Decoding: temperature 0, `response_format=json_object`, 2,000 output tokens, at most 12,000 input tokens. Inputs over the cap retain the warning.

Calls: one logical call per warning per LLM arm, plus one fixed schema-repair retry that is logged. Concurrency is 3.

Caps: 1,500 uncached requests and 12M tokens. Stability: 30 development and test warnings, stratified by arm decision and drawn by a seeded rule, with 3 fresh replicates and the cache bypassed via the replicate ID.

## Leakage controls

- Model inputs never contain labels, expected-result files, test IDs, advisory text or commit messages. Files are shown as `case.py`.
- OWASP test cases are not opened, run or scored until the protocol, policy, prompts and code are committed and frozen with the tag `protocol-freeze`.

## Freeze record (tag `protocol-freeze`)

Implementation details fixed during development, before any test-split data was opened:

- **Frozen artifacts:**
  - Semgrep rule `baseline/rules/cwe22-taint.yaml`, SHA-256 `9afd5c32…535f`, Semgrep CE 1.182.1.
  - OWASP split `data/owasp_split.csv` `3e28943b…0053`: development 34 cases / 7 families, test 134 / 61.
  - Diagnostic manifest `30c50165…ab41`: development 12 pairs / 12 families, held-out 24 pairs / 12 families, all labels mechanically validated (`data/diagnostics/label_validation.csv`).
  - Prompts version `p2`, concatenated SHA-256 `5d54c4d1…0d00`.
- **Known baseline limitation:** Semgrep CE 1.182.1 does not propagate taint through Python slices (`s[a:b]`). Propagators, rule options and taint labels did not change this. All 3 development false negatives have this cause. It is reported as an engine limitation; the rule is not altered for it.
- **Extractor scope:**
  - Assignments, augmented assignment, `if`/`match` with constant folding.
  - Loops iterated to a fixpoint (≤ 5 rounds, otherwise widened and marked incomplete); `break`/`continue` exits joined.
  - `try`: handler entry is the join of all prefix states.
  - `with`; non-returning calls (`flask.abort`, `sys.exit`).
  - Local lists and dicts with element-level values. Assigning a container to a second name marks the analysis incomplete.
  - Unmodelled functions propagate their inputs, as Semgrep's default does.
- **EC suppression rule** (as above): structural checks plus, for non-standard guards, the model's confinement claim citing the guard. Such cases are reported as `semantic_judgment_remaining`.
- **Bootstrap clusters:** OWASP flow-template family; diagnostics semantic family (both pairs of a family together).
- **Transport:** SoCLaaS rate-limits bursts of long prompts (`RateLimitError` seen at concurrency 3). The client retries transport errors with exponential backoff (honouring `Retry-After`) up to 7 attempts, and logs the retry count. Model answers are never retried except for the single schema-repair retry.
