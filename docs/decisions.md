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

## 2026-10-22: Development iterations (all on development data)

| Iteration | Change | Evidence (development runs in `results/runs/`) |
|---|---|---|
| Rule v1 | Taint rule with project sources, helper contracts, container and config propagators | `dev-offline-D`: S TP 4, FP 21, FN 3 on OWASP dev |
| Slices | Tried slice propagators, rule options and taint labels; none restore taint through `s[a:b]`; kept as a documented engine limitation | Probe files in the session log; all 3 dev FN are slices |
| Extractor: loop exits | `break`/`continue` states were dropped, so 00618 (vulnerable) looked constant. Fixed: exits rejoin after the loop | Regression test `test_loop_break_carries_taint` |
| Extractor: loops | Single-pass loops forced "incomplete" on 2 provable dev cases; replaced with fixpoint iteration plus widening | `test_loop_over_constants_reaches_fixpoint`, `test_non_converging_loop_is_incomplete` |
| Guard coverage | "Same value" was a variable-name test; replaced with a dependency-slice cut (no tainted origin reachable without crossing the guarded definitions) | `test_blocklist_guard_covers_but_is_not_sound`, `test_one_guarded_branch_does_not_cover_alternative` |
| Prompts p1 → p2 | p1: E ignored deterministic facts and confused reason kinds; the gate rejected 4 of 6 E suppressions, and 2 of them cited real but unlisted definitions. p2: facts digest before the JSON, precise reason-kind definitions (shared system prompt, so L benefits too), every definition listed with `in_sink_slice` | `dev-smoke` (p1): E FP-removal 0.286, EC 0.095. `dev-p2`: E 0.857, EC 0.857 |
| Rate limits | 17/25 E calls failed with `RateLimitError` at concurrency 3. Added transport backoff | `dev-p2` rerun: 0 failures, 7 retries |
| Output tolerance | Accept obligations given as bare status strings (1 dev reply) | `test_validate_rejects_malformed` |
| abort() | `if bad: abort(403)` was not treated as an exit, so no guard was recognised. Non-returning calls now end the path | `test_sound_containment_commonpath` |
| Identity masking | Route paths leaked the category (`/benchmark/pathtraver-00/`); masked with test IDs | `test_prompts_never_contain_labels_or_case_ids` |
| Aliasing | `alias = parts; alias.append(x)` would have been treated as not mutating `parts` (D would wrongly suppress); container aliasing now marks the analysis incomplete | `test_container_alias_is_incomplete` |
| Diagnostic labels | The validator rejected 4 intended labels: both `checked_vs_original` "vulnerable" programs were safe (normalised and raw joins coincide without symlinks), and the `guard_other_value` validator gave both inputs the same payload. Redesigned the first two with decode-after-check; the validator now varies input groups independently | `label_validation.csv`: 72/72 agree |

Final development numbers before freezing (`dev-final-owasp`, `dev-final-diag`):

- **OWASP dev (34 cases):** D, E and EC all remove 19/21 false positives with full TP retention; L removes 4/21.
- **Diagnostic dev (24 programs):** D removes 5/10 false positives, 0 wrongful; L 9/10 with 3 wrongful; E 8/10 with 1 wrongful; EC 7/10 with 1 wrongful (`semantic_judgment_remaining`: `re.match` taken as a full allow-list).

## 2026-10-22: After protocol-freeze

No frozen file was changed; `git diff protocol-freeze` over the frozen paths is empty.

- **Real-world selection amended before any real-world run.** The screening rule (3 projects) produced 5 target pairs, below the protocol's 6–10. Amended the rule to "at least 3 projects, add projects in the same deterministic order (up to 4) while there are fewer than 6 pairs". This added `corydolphin/flask-cors`, giving 6 pairs in 4 projects. The change was made before S or any arm was run on real-world code, and does not depend on method results. 45 of the 51 screened commits were rejected: 38 not using Flask request APIs in the changed files, 6 by the project cap, 1 inaccessible commit, 1 with no non-test Python change.
- **Failure analysis on test data** (no tuning):
  - S's 23 OWASP misses are slices (15, one also a dict store) and dict-store-then-read-by-key (8): Semgrep CE engine limitations.
  - D's 21 kept false positives are a `'../'` block-list (8), an always-failing relative prefix check (5), ConfigParser key separation (4) and a `request.path` segment fixed by routing (4).
- **Post-hoc EC+** (`src/neurosym/extension.py`): two extra gate checks, designed *after* seeing the two wrongful EC suppressions on the held-out pairs. It replays the frozen E responses with no new calls and is reported only as exploratory.
  - Held-out pairs: TP retention 0.913 → 1.000, FP removal 0.789 → 0.737.
  - OWASP test: unchanged.
  - OWASP dev: FP removal 0.905 → 0.762. E gave unsound guards as the reason for values that were actually constant.

## 2026-10-23: Post-review correctness correction (D-R1, tag `review-correction-1`)

An independent adversarial review (`docs/review/gptpro-2026-10-23/`) found programs for which the frozen extractor reported **complete** evidence while the warning was real, so D suppressed a true vulnerability. The witnesses are conditional on Semgrep alerting at the sink. All were confirmed, and while fixing them 16 more programs of the same kinds were found. They are all now regression tests (`tests/test_review_regressions.py`, 22 unsafe and 6 safe programs).

| Class | Frozen behaviour | Correction |
|---|---|---|
| Containment roles | `commonpath([R, v]) == v` was accepted (it checks that v contains R) | The compared side must be the non-candidate element |
| Containment root | `v.startswith(root + '/')` was accepted with `root` from the request | The root must be built from constants, module constants or untainted locals whose definitions reach both guard and sink, and (if concrete) be an absolute path other than `/` |
| Loop `else` | Applied after `break` exits were joined | Jump exits bypass `else` |
| `try`/`finally` | States at `return` (and exceptions raised in nested blocks) never reached `finally`. Handler entry joined only top-level prefix states | Every state from which the body may raise (nested blocks included) reaches handlers. A `finally` containing the sink also sees abrupt completions. `break`/`continue` through `finally` and `contextlib.suppress` mark the analysis incomplete |
| Aliasing | Only `alias = container` was detected | Also flagged: chained assignment, a container stored in a container or attribute, passed to an unmodelled call, or iterated as a nested element |
| Unmodelled code | `*args`, `**kwargs`, positional-only parameters, `match` captures other than a top-level name, module objects mutated by some function, and calls to functions defined in the module were treated as trusted constants | All are unknown (or tainted if given tainted arguments). Calls to nested functions mark the analysis incomplete. An unmodelled call given attacker data taints the mutable locals it receives |

**Effect on the archived results** (`scripts/compare_evidence.py`, saved in `results/corrections/compare_evidence.json`): re-extracting every archived alert gives **byte-identical evidence records for all 220 held-out benchmark alerts** (OWASP test 2 × 68, diagnostics 2 × 42) and for the final development runs (`dev-final-*`, `dev-p2`). Two earlier development runs made with older extractor versions (`dev-smoke`, `dev-offline-D`) differ, as expected. The E prompts are therefore identical, the archived E responses answer exactly the same inputs, and D and EC decisions are unchanged. The frozen benchmark results stand as reported. One choice kept this true without losing soundness: handlers also see the completed try body's state (an over-approximation the frozen analysis already made). The 16 real-world evidence records changed. D is still `retain` for all of them; their E inputs changed, so only those E calls were regenerated in the correction runs `corr-rw-*`.

**Correction runs.** `corr-*` runs use the corrected code, checked against tag `review-correction-1` (`--correction`). Benchmark correction runs replay the archived responses offline. Frozen runs are never overwritten; `pipeline.run` now refuses an existing run name.

**What the correction does not change.** EC checks *dependency consistency*: the cited guard dominates the sink, and every tainted flow passes through a definition the guard reads. It does not check that the checked value is the consumed value. A later transformation (`target + '/../x'` after a check on `target`) passes the structural check. Such suppressions are categorised `semantic_judgment_remaining`, never `trusted_contract_matched`, and `test_gate_is_a_dependency_filter_not_value_identity` documents this. The report describes EC accordingly. D's containment recognizer is identity-checked: the guard must read the exact definition the sink consumes.

## 2026-10-23: Evaluation and claim corrections after the review (no new model calls except the 16 real-world E prompts above)

- **Real-world scoring** now uses a manual per-warning defect mapping (`data/realworld/target_adjudication.csv`, `alert_adjudication.csv`), made from fix diffs and code without looking at arm decisions. Two targets are outside the task: flask-cors (CORS matching) and mlflow `cf83dad4df` (Windows drive letters). The whoogle `send_file(BytesIO)` warning is unrelated. The mlflow `5044878da0` warnings are fix-related; their exploitability at the local sink is not established. This is a retrospective adjudication and is labelled as such.
- **Diagnostic validator:** three outcomes (witness / no witness / inconclusive); expected rejections are counted separately from other errors. The benign inputs `7` and `a.txt` were added so that `numeric_id1_safe` and `allowlist1_safe` (both development fixtures) exercise their accepting paths. Every safe fixture has a static justification (`data/diagnostics/safe_justification.csv`). Labels are unchanged: 72/72 agree.
- **Offline analyses added:** OWASP label sensitivity excluding the 8 ambiguous block-list cases (`results/tables/sensitivity.md`); decision status and fallback counts (`status.md`); the gate's cost and benefit (`gate.md`). Main, diagnostic and difference tables are unchanged.
- **Stability raw replies** exported by an offline replay that reproduces `stability.json` exactly (`results/stability_responses.jsonl`).
- **Report:** claims narrowed per the review (see `docs/review/gptpro-2026-10-23/RESPONSE.md`).
