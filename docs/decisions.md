# Design decisions and iterations

The report's Approach section must describe the important iterations, including abandoned ones. Add an entry whenever the design changes.

Format: date, what changed, why, and evidence (run, commit or result file).

## 2026-10-22: Infrastructure

- SoCLaaS via an OpenAI-compatible client, wrapped so every call is cached by request hash and logged with the served model, tokens and latency. This gives reproducible reruns and the resource budget the report must state.
- The `default` model alias served `qwen3.6:35b`. Reported experiments will pin a concrete model ID.

## 2026-10-22: Project selected; Gates 0 and 1

- Adopted the plan in `docs/plan/PLAN.md`: Python CWE-22 path-traversal warning refinement, with arms S/D/L/E/EC. Replaces the earlier Python command-injection idea. Why: the OWASP Python benchmark has 168 path-traversal cases (65 vulnerable) vs 20 command-injection cases, and the plan positions the work against LLMDFA, IRIS, ZeroFalse and related work.
- Baseline: Semgrep CE 1.182.1. Its JSON and SARIF output contain no dataflow traces without login, so all flow evidence is built by our own AST analysis. Intraprocedural scope confirmed on fixtures (`docs/feasibility.md`).
- The community Flask path-traversal rule is pattern-based and only covers `open()`. Proposed: a project-authored frozen taint policy as the primary baseline, with the community rule as a reference row. Awaiting Yufan's review.
- Benchmark helpers (`request_wrapper`, `ThingFactory`, `get_parameter`) proposed as shared, versioned API contracts. Awaiting review.
- `qwen3.5:9b` is a reasoning model; `reasoning_effort="none"` disables reasoning. Choice of setting awaiting review.
- Folder mapping: `subjects/` renamed to `data/`; added `configs/` and `tests/`; the plan's `analyzer/`, `prompts/` and `evaluation/` map to `src/neurosym/`, `src/neurosym/prompts/` and `eval/`.

## 2026-10-22: Protocol decisions (resolved with GPT Pro; see `docs/protocol.md`)

- **D vs EC boundary fixed in advance.** Before freezing, the review found that if D's recognizers equalled the gate's acceptance conditions, EC could never beat D, and the comparison would be decided by how D is coded. Resolution: D is a closed list of provable recognizers (constant overwrite, infeasible branch, safe API with preconditions, sound containment). The EC gate checks structure only (guard exists, dominates, same value, no redefinition, coverage). A non-standard guard predicate is an LLM semantic judgment, logged as `semantic_judgment_remaining`. EC can therefore differ from D only on those cases, and that is measured, not assumed.
- **Strong baseline.** The benchmark helper contracts (including the constant-returning `get_safe_value`) go into the Semgrep policy rather than being left for refinement. This leaves fewer false positives to filter, but weakening the baseline would make any gain meaningless.
- **OWASP development split.** About 30 development cases, grouped by flow template so that no template is shared between development and test. Reason: writing the rule and recognizers without seeing any benchmark code means guessing its idioms, and peeking informally is worse than a declared split. The exposed case 00008's family goes to development.
- **Real-world selection.** TP retention needs targets that S actually reports, so retention is measured only on S-reported targets, and S's coverage of every target is reported. Selection uses feasibility criteria only.
- **Diagnostic labels validated mechanically.** A stubbed-filesystem harness runs payloads against each fixture. This is an independent check that does not rely on the author's intended label. It is used only for ground truth, never by the analyzer.
- **Small model:** `qwen3.5:9b` with `reasoning_effort="none"`, the same non-thinking regime as the primary model.
