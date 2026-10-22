# CS6215 implementation handoff: research-grounded project plan

Prepared for Yufan Zhu, 22 October 2026 (Singapore time).
Target workspace supplied by the user: `/Volumes/Storage/projects/cs6215-neurosym`.

## Status and boundaries

This document specifies a proposed course project. It is not an experimental-results report. The planning assistant reviewed the supplied six-page course specification, primary research papers, official tool documentation, and benchmark documentation/source pages. It has NOT inspected or modified the user's Mac workspace, verified the local client, or run Semgrep/SoCLaaS experiments. Model availability, the existing repository structure, the working API call, and the compiling report skeleton are user-supplied information.

Keep the existing project, client, `.env`, report skeleton, and design log. Do not reinitialize the repository. Never print credentials, send `.env` to a model, or put secrets in caches or public artifacts. Do not publish the repository without the user's authorization. Preparing a GitHub-ready artifact is authorized by this plan; publication is a separate external action.

## 1. Selected project

**Working title:** Evidence-Checked LLM Triage for Python Path-Traversal Warnings: A Comparative Static-Analysis Study.

**Central question:** Does requiring an LLM's suppression decisions to agree with explicit program evidence reduce false warnings without unnecessarily discarding real vulnerabilities, compared with a symbolic analyzer, deterministic refinement, and ordinary LLM triage?

The task is deliberately warning refinement, not universal vulnerability discovery. The delivered analyzer runs a symbolic baseline and then applies a student-designed neuro-symbolic refinement procedure. It is still static: it inspects code without executing the analyzed application. Unit tests of the implementation and independently established benchmark labels are not part of the inference procedure.

**Language / weakness / platform:** Python; CWE-22 path traversal; initially POSIX path semantics. Include unauthorized filesystem access and metadata/existence probing, not only file reads. This matters because OWASP Python includes cases using `Path.exists()`.

**Resources:** CPU-based static analysis and preprocessing on the Mac; inference through the user's existing SoCLaaS client. No local GPU, training, fine-tuning, Java, Android toolchain, or paid API is a project dependency.

**Not a novelty claim:** LLM-assisted static analysis, LLM false-positive filtering, structured evidence, and verification are established ideas. The submission must present the student's particular implementation, analysis-specific decisions, controlled comparisons, and findings. Do not call the system the first, state of the art, sound, complete, or formally verified.

## 2. Course requirements and rubric mapping

Authority: the supplied `course-project-doc.pdf`, especially Sections 1–6. If another local handout conflicts, identify the conflict explicitly rather than silently selecting a convenient interpretation.

| Rubric component | Weight | Required project evidence |
| --- | ---: | --- |
| Preliminaries | 10% | Precise CWE-22 target, threat model, analysis scope, source/sink/sanitizer policy, and an explanation of Semgrep taint analysis in the student's own words. |
| Evaluation setting | 10% | Version-pinned subjects and rules, auditable labels, predeclared comparison units, development/test separation, fair candidate sets, and resource accounting. |
| Neuro-symbolic design and implementation | 30% | Independently written Python evidence representation, scoped control/data-flow extraction, structured model interface, evidence checks, abstention policy, tests, and design iterations. |
| Comparative evaluation and findings | 30% | Symbolic, deterministic-refinement, ordinary-LLM, structured-LLM, and evidence-checked comparisons; FP removal AND TP retention; failure analysis and negative findings. |
| Writing quality | 10% | Clear 6–10-page ACM sigconf report, correct limits, appropriately bounded claims, and accurate AI Usage Statement. |
| Artifact and reproducibility | 10% | Publicly accessible repository by submission, dependencies and snapshot manifests, runnable scripts, prompts, sanitized outputs, reproduction instructions, and smoke tests. |

The report is English PDF using `\documentclass[sigconf]{acmart}`. Main text is 6–10 pages INCLUDING figures, tables, appendices, and AI Usage Statement; at most one extra references page. Include the student's name and identifier in the submitted report and the public artifact URL. No project oral presentation. Deadline: **30 November 2026, 23:59 Singapore time**.

The requirement is student-designed exploration, not necessarily research-level novelty or superiority. Do not clone an existing neuro-symbolic analyzer and submit a renamed or Python-ported version. Claude is implementation assistance, not a substitute for accurately identifying the student's actual decisions and review.

A static-analysis topic does not require a separate topic-approval email under Section 6. Do not silently turn the project into fuzzing, exploit generation, or another dynamic-analysis project.

## 3. Literature positioning and exclusions

Read the relevant method sections, not only abstracts. Maintain `docs/literature.md` with the source version, inspected sections, relevant mechanism, overlap, and the project's concrete difference.

| Prior work | Verified relevant mechanism | Consequence for this project |
| --- | --- | --- |
| LLMDFA, NeurIPS 2024 | Source/sink extraction, LLM function summaries, and path-feasibility validation with external tools. | Do not claim compilation-free LLM dataflow reasoning is new. Do not reuse its prompts, summarization workflow, or implementation as the main solution. |
| IRIS, ICLR 2025 | LLM-inferred taint specifications, CodeQL analysis, and contextual filtering of alerts. | Do not claim 'static analyzer + LLM' or improved API modeling is new. Our main experiment freezes the symbolic candidate set rather than learning specifications. |
| ZeroFalse, 2025 preprint version inspected | Canonicalized static alerts enriched with flow-sensitive context and CWE-specific, structured LLM adjudication. | Very close conceptual work. Structured prompts alone are not a novelty claim. Independently implement and test value-identity, guard-dominance, coverage, and abstention checks; do not port its workflow. |
| LLM4PFA, 2025 preprint version inspected | Iterative interprocedural feasibility reasoning and LLM-to-SMT constraint solving. | Do not build an ambitious solver-based interprocedural framework for this course. Scope is bounded and unsupported constructs remain unresolved. |
| Sifting the Noise, 27 June 2026 version | Comparison of LLM agents for false-positive filtering, including suppression of genuine vulnerabilities. | Measure real-vulnerability retention explicitly. The cited 22.25% miss rate is that study's result, not a forecast or target for this project. |
| PySeType, 14 August 2026 preprint | Semantic type inference/checking integrated with Python static analysis. | Python neuro-symbolic vulnerability analysis already exists. Do not reproduce its semantic type system or broad whole-program architecture. |
| Memoir, 10 August 2026 preprint | Retrieval, verification, and evolution of reusable false-positive memories. | Do not add memory/RAG/training as scope creep or claim invariant-based checking is new. |

Additional surrounding work inspected during planning includes MoCQ (LLM-generated static queries), Argus (multi-agent vulnerability analysis), and Vulnhuntr (existing Python LLM vulnerability discovery). These are related work, not the submitted method or infrastructure to wrap and rename.

**Specific student-designed choices to document:** the path-traversal obligation schema; how evidence is computed rather than hallucinated; variable-definition identity; checks for guarding the actual sink value; treatment of alternate flows and missing context; the retention rule; fair comparison arms; and paired semantic stress tests. Their usefulness must be measured. They are not asserted to be globally novel.

## 4. Formal task and claims

Let `P` be a pinned program snapshot, `Sigma` the frozen source/sink/API policy, and `A = B(P, Sigma)` the alerts emitted by the symbolic baseline. For an alert `a`, deterministic preprocessing builds evidence `E(a)`. The LLM proposes:

`g(E(a)) = (decision, reason_kind, evidence_node_ids, assumptions)`

where `decision` is `retain`, `suppress`, or `unknown`.

A deterministic checker returns `pass`, `fail`, or `unknown` for the claimed evidence. The final retained set is:

`R = {a in A : NOT (g(E(a)).decision == suppress AND check(a, E(a), g(E(a))) == pass)}`.

Timeouts, malformed outputs, missing facts, unsupported analysis constructs, and unresolved alternative flows therefore retain the warning. Preserve raw and checked decisions separately.

By construction, `R` is a subset of `A`. With the same scoring unit and gold-positive set, this method cannot improve recall beyond the underlying baseline. It may improve precision, may worsen recall, or may add no useful benefit. An observed end-to-end recall increase implies a comparison/matching error or an unreported candidate-discovery change.

**Important distinction:** code-location and control/data-flow checks are not a proof that every LLM semantic judgment is correct. The prototype does not provide a general soundness guarantee for Python. No alert is called 'proved safe' merely because its node IDs exist.

### Threat model and supported scope

The attacker controls explicitly configured HTTP inputs, including relevant request fields, cookies, and route arguments. A public function parameter is a source only under an explicitly recorded entrypoint assumption; not every parameter is automatically attacker-controlled. The trusted directory/root and any external API contracts must be specified.

Primary controlled comparison uses intraprocedural analysis. Semgrep CE does not supply Pro's interprocedural taint capabilities. Distinguish local flow from helper/cross-file flow in all results. Additional helper context is optional and must be a separate stratum or matched-context ablation, not a hidden advantage.

The initial implementation supports assignments, simple aliases, joins/formatting, ordinary `if` branches, early `return`/`raise`, and manually specified API contracts. Loops, complex exceptions, dynamic imports/dispatch, reflective access, mutation through aliases, unresolved external calls, or incomplete reaching definitions make dependent suppression claims unknown unless an explicitly tested conservative treatment exists.

Do not assume POSIX checks secure Windows paths. Symlink attacks, adversarial filesystem mutation, and time-of-check/time-of-use races are outside the initial lexical path-traversal scope. Mark benchmark subjects requiring those threat models separately; do not relabel them safe.

## 5. Symbolic baseline and fairness

**Primary baseline:** pinned Semgrep Community Edition in taint mode, with a frozen, documented Python CWE-22 policy. Semgrep is the established engine; the chosen source/sink rules are its configuration. If rules are authored or adapted for this project, say so explicitly. Do not label this configuration an unmodified published state-of-the-art analyzer.

Inspect relevant community rules where obtainable; record origin and revision for each reused rule. Source/sink support and documented safe APIs must be reasonable, not intentionally impoverished to make the LLM win. Test supported positive flows and safe cases before freezing. Reuse the SAME baseline output for every filtering arm.

Do not use an automatically updating `--config=auto` or a mutable registry rule pack as the sole reproducibility specification. Do not enable paid Pro features in a nominally CE experiment. Record engine version, rules hash, Python version, OS/architecture, flags, timeouts, exclusions, and exit status.

Use JSON for findings and archive SARIF/text traces when available. The official CLI documentation says `--dataflow-traces` affects text and SARIF; do not assume that flag alone guarantees a particular JSON trace schema. Write and test an adapter against the actual pinned output. Missing traces remain missing; they are not invented by the model.

CodeQL's existing `py/path-injection` query is an optional stronger reference baseline, not a required dependency. Add it only after the complete primary study works and installation/eligibility is verified. Do not postpone the project to install several analysis frameworks.

## 6. Student-designed analyzer

### 6.1 Canonical alerts and evidence

Normalize each finding to a canonical target using repository revision, file content hash, function scope, sink span, weakness, and policy. Preserve multiple incoming source paths; deduplicating alerts must not discard alternatives relevant to safety.

Create an `EvidenceRecord` containing:

- The canonical alert and raw baseline reference.
- Numbered AST nodes with file hash and source spans.
- Known source and sink expressions and argument positions.
- Relevant assignments/definitions and possible incoming values.
- Branch predicates and applicable dominance relationships.
- Transformations applied to the actual sink value.
- Trusted-root facts and explicitly versioned API contracts.
- Per-fact provenance and coverage/unknown flags.

A string mention or matching variable name is not a definition-use relationship. Represent value identity with scope and reaching definition, not the textual identifier alone.

### 6.2 LLM obligations

Ask the model to assess four obligations using only supplied code and recorded contracts:

1. **Control:** Is the relevant value attacker-controlled under the stated entrypoint model?
2. **Flow:** Can that value affect this particular filesystem path argument?
3. **Confinement:** Is there a relevant confinement condition or trusted safe API, and does it concern the value actually used?
4. **Coverage:** Does the evidence justify suppression for the whole reported target rather than one benign path?

Output compact structured reasons and node references, not an unrestricted essay or unsupported exploit story. Natural-language comments are untrusted data, not instructions or evidence of safety. Never request hidden chain-of-thought; concise checkable rationales are sufficient.

Allowed reason kinds:

- `constant_or_overwritten_value`
- `unreachable_reported_flow`
- `guarded_path_confinement`
- `trusted_base_safe_api`
- `unresolved`

The model is not allowed to create new nodes, execute shell commands, browse the internet, read labels, or change the policy during analysis.

### 6.3 Deterministic evidence checks

Check schema validity; existence of cited nodes; correct scope and snapshot; source/sink identity; whether a purported guard actually guards the sink; whether the checked value is the consumed value; whether a subsequent reassignment invalidates the argument; and whether unresolved alternative incoming flows remain.

For a constant/overwrite claim, incomplete reaching definitions or unmodeled mutation invalidate suppression. For an unreachable-flow claim, a single infeasible trace does not establish that every route to the sink is infeasible. For a safe-API claim, verify documented preconditions, including trusted base-directory arguments.

The checker should distinguish:

- `structural_check_passed`: the evidence is consistent with extracted static facts;
- `trusted_contract_matched`: a manually specified API contract and its preconditions apply;
- `semantic_judgment_remaining`: part of the conclusion still rests on LLM interpretation.

These distinctions must survive into logs and failure analysis. Passing structural checks alone is NOT a semantic proof. Pre-register exactly which combinations permit suppression. A practical initial rule permits suppression only when all required structural checks pass, the evidence is complete for that claim, and the model gives an explicit in-scope confinement argument or a trusted contract applies. This is an empirical heuristic, not verified safety.

Unsupported syntax or partial context must never be silently interpreted as absence of a flow. The default is to keep the warning.

### 6.4 Why include a symbolic-only refinement?

The deterministic-only arm automatically applies the project's fixed, explicit recognizers, without a model choosing or interpreting evidence. It gets the same extracted program information and trusted contracts. This prevents attributing easy improvements from constant propagation, known library contracts, or guard recognition to an LLM.

Do not intentionally cripple this arm. If it matches or outperforms the full method, report that the LLM was unnecessary for the tested scope. This is a legitimate course finding.

## 7. Concrete motivating cases and implementation tests

A useful paired example is a guard that checks a normalized path `candidate` while the sink uses the original user input `name`. A nearby normalizing call or reassuring function name is not enough; safety depends on the value consumed at the sink. The benign partner uses the checked value, with root/path assumptions stated.

Other test families:

- Tainted value overwritten by a trusted constant versus tainted overwrite after validation.
- Guard on the consumed variable versus guard on a different variable.
- Reject branch returns/raises versus reject branch only logs and continues.
- Constant trusted base in `send_from_directory` versus attacker-controlled directory argument.
- `commonpath` containment under stated preconditions versus string-prefix confusion.
- Canonicalization alone versus an actual containment check.
- Relative traversal versus absolute-path replacement in a join.
- One protected incoming branch versus an unprotected alternative branch.
- A helper named `sanitize` with an ineffective body versus a demonstrably relevant check.
- An unreachable reported path versus another reachable path to the same sink.
- Local aliases versus unknown mutation/dynamic behavior, which must cause abstention.
- Metadata/existence probing versus only file-read sinks.

These are specification/test ideas, not already implemented results. Check language/API semantics against the pinned official documentation. Do not execute downloaded vulnerable applications or generate network attacks as part of this project.

## 8. Evaluation subjects and ground truth

### A. External benchmark: OWASP Benchmark for Python

Official v0.1 documentation lists 1,230 total cases, including **168 path-traversal** and **20 command-injection** cases. These are published inventory figures, not a measured final selected sample. Pin the repository revision and recompute the inventory and positive/negative distribution from the corresponding `expectedresults-0.1.csv`.

This is why path traversal is preferred over the earlier command-injection suggestion: it provides a larger independently supplied CWE-specific benchmark. Do not run all CWEs.

Label-quality precautions are mandatory. The repository calls v0.1 preliminary. Issue #1 discusses an older incorrect path-traversal case; the maintainer says it was fixed. The current inspected source for `BenchmarkTest00008.py` contains `bar = param` in the reachable branch, unlike the older code quoted in the issue. Do not claim the historical issue proves the current snapshot is still mislabeled.

Preserve original labels. Separately record adjudicated labels, evidence, date, and reasons in `data/adjudications.csv`. A model prediction or a baseline warning is not ground truth. Review disagreements independently of which system benefits; report scores against official labels and a clearly named adjudicated sensitivity set if necessary. Ambiguous labels remain ambiguous.

Development exposure matters: `BenchmarkTest00008` was inspected during planning. Mark it design-exposed rather than calling every OWASP case untouched. Publish the full benchmark score and a separately identified confirmatory subset excluding any development-exposed families. Do not inspect test outcomes to tune the prompts or rules.

Exclude label files, expected results, advisory narratives, and result-bearing comments from model inputs. Use opaque display identifiers and keep mappings outside inference. Preserve program semantics; do not indiscriminately replace string literals. Identifier-renamed variants are a robustness test, not proof that pretraining contamination is absent.

### B. Diagnostic pairs: proposed, not collected

Prepare **12 development pairs (24 programs)** and **24 held-out pairs (48 programs)**. Each pair contains a security-relevant difference, with an independently reviewed expected relation. Keep template/AST families separate between development and test; superficial renaming does not make a new independent family.

Optionally create one semantics-preserving renamed/aliased variant for each held-out program, adding 48 derivative tests. Count these as clustered transformations of the original 24 pairs, not 48 independent vulnerabilities. Clearly distinguish handcrafted fixtures from external or real-world code.

Tests should be designed to discriminate value identity, guard polarity, dominance, trusted-base assumptions, and alternate-flow handling—not chosen after seeing which examples make our method win.

### C. Real-world case studies

Target **3 distinct archived Python projects**, with approximately **6–10 documented vulnerable/fixed target pairs in total**, selected from accessible Python CWE-22 records in PyVul. Four projects are optional. These are targets, not verified inventory or completed analyses.

Use PyVul's commit-level records and repository acquisition scripts, not only isolated function labels. Before committing to cases, verify the advisory, language, vulnerable revision, actual fix, target operation, source assumptions, and local/cross-function scope. Use a deterministic selection rule based on these feasibility properties, not the method's accuracy. Record rejected candidates and why.

Do not assume every modified function is vulnerable or the entire fixed repository is safe. A fixed target can be a negative only for the verified defect and stated assumptions. Additional alerts are unlabeled until reviewed. Report known-target hit rates and reviewed-alert outcomes; do not claim complete repository recall.

If the selected real-world cases are mostly outside CE's supported scope, report the misses rather than relabeling them. They can be useful limitation cases. A benchmark-focused course project is permitted; do not substitute toy applications for real projects without clearly stating the change.

## 9. Experimental arms

Use the same baseline candidates, source context, model, prompt token cap, and timeout where applicable.

| ID | Configuration | Purpose |
| --- | --- | --- |
| S | Semgrep CE with frozen policy | Required symbolic baseline. |
| D | S plus deterministic-only refinement | Tests whether ordinary symbolic refinements explain the gains. |
| L | S plus ordinary LLM triage on raw code/context | Tests whether adding a model helps without our structured representation. |
| E | S plus structured-evidence LLM triage, no evidence gate | Isolates the representation and obligation prompts. |
| EC | Same E outputs plus evidence gate and conservative retention | Main proposed neuro-symbolic system. |

E and EC MUST consume the same cached model response for the gating ablation; rerunning the LLM would confound the effect of the gate with generation variation. Compare L and E under matched source context and maximum token budgets. If E's enriched representation exceeds the budget, flag the instance and handle it consistently rather than silently giving more information.

Optional reference: a direct LLM detector on a fixed set of complete subjects, without baseline alerts. This is not necessary for the primary claim and should be omitted before sacrificing core controls. Optional second symbolic baseline: CodeQL. Do not use existing neuro-symbolic tools as the submitted solution.

### Research questions

RQ1: What FP-removal / TP-retention trade-off does each configuration achieve?

RQ2: Do structured evidence and deterministic checking add value beyond ordinary prompting and deterministic-only refinement?

RQ3: Which semantic situations cause improvement, harm, abstention, or no benefit, and how does behavior change under paired edits and semantics-preserving transformations?

RQ4 (small secondary study): Are findings stable across fresh generations and a smaller model, and what resources are consumed?

## 10. Scoring protocol

Choose and document the scoring unit BEFORE collecting results. For official OWASP scores, use the benchmark's target testcase unit; multiple findings do not count as multiple true vulnerabilities. The case remains reported if any matching target warning remains. Sink-level or source/sink-level diagnostics are separate tables and must not be mixed with testcase-level metrics.

For a consistent unit, let G be gold positives, A baseline-reported units, and R retained units:

- Precision = `|R intersect G| / |R|`.
- End-to-end recall = `|R intersect G| / |G|`.
- TP retention = `|R intersect G| / |A intersect G|`.
- FP removal = `|(A minus R) minus G| / |A minus G|`.
- Wrongful suppression count = `|(A minus R) intersect G|`.

When denominators are zero, report N/A and counts, not invented perfect values. Include F1, raw TP/FP/FN/TN where appropriate, abstention rate, invalid-output rate, analysis coverage, and tool/API failure counts. For refinement arms, failures retain baseline alerts. If the baseline itself fails, report the coverage failure; do not silently count the subject as clean.

The identity `end_to_end_recall = baseline_recall * TP_retention` holds under aligned scoring units. Test it in the scorer. A candidate-only triage score is not overall detection recall.

For paired tests, report pair accuracy: both the vulnerable and safe partner must be correct. For transformed programs, report prediction consistency AND correctness so an always-constant predictor cannot look good.

Use paired comparisons and cluster-aware uncertainty (by template family or project where feasible). On tiny real-world samples, give counts and individual cases rather than confident population-level claims. Do not bootstrap near-duplicate renamed examples as independent observations.

Do not pick a suppression threshold or policy on held-out scores. Report all prespecified configurations, including worse or inconclusive ones. No target F1 or required improvement is set.

## 11. Models, API configuration, and resource budget

Use the existing centralized client. The user's supplied services include `qwen3-coder-next`, `qwen3.6:35b`, `qwen3.8:27b`, `ornith1.5:35b`, `gemma4:26b`, `qwen3.5:9b`, and `llama3.1:8b`. This is a user-reported service inventory, not an independently verified architecture claim.

Prespecify **`qwen3-coder-next` as the primary model** and **`qwen3.5:9b` as a small-model check**. The rationale is their reported availability and coding-oriented versus smaller role, not evidence that either is best. Only switch the primary for a recorded service/compatibility failure before test runs, not because test accuracy is disappointing. `qwen3.6:35b` is a reasonable availability fallback. Do not call `default` in reported experiments.

Use minimal agentism: deterministic analysis, a bounded model call, and deterministic postprocessing. No multi-agent debate, RAG, online prompt optimization, or model tournament. Start with one logical call per alert for each prompt arm; transport retries and any fixed schema-repair retry must be logged and budgeted. Do not selectively retry wrong answers.

Initial proposed caps: **1,500 uncached requests and 12 million total tokens** across the planned study. These are limits, not measured needs or a guarantee all optional experiments fit. Reserve budget for pilot failures and stability runs. Use a modest fixed context budget (e.g. 12,000 input tokens plus 2,000 output tokens) rather than the entire reported 262k context. Start at concurrency 2 unless service guidance permits more; respect rate limits. Record truncated/incomplete evidence and retain affected warnings.

The supplied course handout says SoCLaaS has no usage charges/token quotas; this does not imply infinite throughput, fixed latency, immutable models, or zero shared compute consumption. No local GPU is needed. Report actual requests/tokens/time even if marginal API charge is zero. Do not extrapolate the user's 0.5-second connectivity test to analysis latency.

### Cache and reproducibility requirements

A replay returns the same stored answer; this is not proof that fresh model inference is deterministic. A fresh stability experiment needs a new call rather than a cache hit.

Cache identity must include model/requested ID, returned identity or available backend fingerprint, system and user prompts, code/evidence hashes, prompt/schema/analysis versions, decoding options, and replicate ID. Store the raw response, parse status, normalized result, token usage, timestamps, cold-call latency, retry metadata, and cache-hit status. Never include secrets.

A named model alias may still be updated by the service. Record run dates and any exposed model revision/fingerprint; disclose when immutable weight identifiers are unavailable. Do not mix silent backend changes into one claimed fixed-model result.

On a prespecified stratified subset (e.g. 30 cases), perform 3 fresh generations for the relevant LLM arms with cache replay bypassed. Keep those runs separate from the main frozen response set and report disagreement. Fixed temperature alone is not evidence of determinism.

Time cold inference separately from cached replay. Replaying a cache must not be reported as model-inference speed or as an independent replicate.

## 12. Repository deliverables and implementation order

Adapt the existing folder names rather than creating a competing framework. The following logical files/components must exist:

- `docs/design.md`: task, threat model, supported syntax, pipeline, claims, and originality boundary.
- `docs/literature.md`: primary sources, overlap, and concrete differences.
- `docs/protocol.md`: prespecified subjects/splits, arms, units, metrics, budgets, and failure handling.
- `docs/decisions.md`: dated choices, attempted versions, abandoned designs, and reasons.
- `configs/`: immutable model IDs, rule hashes, analysis scope, thresholds/policies, and timeouts.
- `baseline/`: acquisition/configuration, rules with attribution, output adapter, and smoke tests.
- `analyzer/`: evidence schema, AST/CFG facts, value identity, prompt construction, output parsing, evidence gate, retention policy.
- `prompts/`: independently written, versioned templates.
- `data/manifest.*`: origins, exact revisions, labels, splits, exposure, family IDs, assumptions, exclusions, and licenses.
- `data/adjudications.csv`: original versus reviewed labels and supporting evidence.
- `evaluation/`: deduplication/matching, metrics, paired tests, uncertainty, resource summary, and failure taxonomy.
- `tests/`: deterministic unit tests, tiny complete pipeline smoke tests, corrupted-output/unknown cases, and scorer identities.
- `results/`: raw outputs or acquisition instructions, normalized predictions, logs, all prespecified results, and generated tables.
- `report/`: existing ACM source, figures/tables generated from saved data, and accurate AI Usage Statement.

Provide commands with these logical functions (names may match the existing scaffold): setup, fetch pinned subjects, run offline tests, run S, run L/E, replay EC gate, evaluate, regenerate report tables, and build report. An offline mock mode is for software tests only and must never feed reported scientific results.

### Mandatory implementation tests

Test that: wrong node IDs cannot suppress; stale file hashes cannot suppress; a guard on a different value cannot suppress; non-dominating guards cannot suppress; a later tainted overwrite invalidates suppression; one safe branch does not erase an unsafe alternative; incomplete slices retain; exceptions/timeouts retain; E and EC use identical raw responses; labels never reach prompts; semantic-pair family splits are preserved; duplicate alerts do not inflate TPs; cached responses are not counted as fresh calls; metric denominator-zero cases yield N/A; and retained outputs remain a subset of baseline outputs.

## 13. Feasibility gates and stopping rules

**Gate 0: existing scaffold audit.** Inspect the user-provided repository and local handouts without exposing `.env`. Verify the actual model response format and cache accounting. Read current files before editing. Preserve existing work and record discrepancies with this plan.

**Gate 1: baseline/data feasibility.** Install/pin CE, run a small development smoke set, inspect real outputs/traces, inventory the current OWASP CWE-22 subset, and inspect PyVul acquisition formats. Produce `docs/feasibility.md` with actual results and unresolved issues. Do not call a literature/tool plan an executed benchmark.

**Gate 2: minimum complete system.** Build the evidence representation, bounded checker, and S/D/L/E/EC path. Every supported construct needs positive and negative tests. No full Python call graph or abstract interpreter is required. Narrow the supported subset and retain unknowns rather than silently approximating away hard code.

**Gate 3: protocol freeze.** Review labels and scope without looking at comparative test scores. Freeze rules, prompts, config, case selections, exposure list, and budgets in a local commit. No arbitrary post-test fixes. If a genuine bug is discovered, version the correction and rerun all affected arms, preserving the original result.

**Gate 4: controlled evaluation.** Run the full fixed protocol, first one model, then small-model and stability checks within budget. Keep all negative outcomes.

**Gate 5: case studies and packaging.** Complete the auditable real-world subset, report writing, replay/live instructions, licenses, and public-artifact readiness.

If the baseline already has very few false positives, report that ceiling and the harm/overhead of adding the LLM. Do not weaken the baseline. If simple deterministic checks explain the improvement, report that. If real-world cases are not feasible, keep the external benchmark plus diagnostic analysis and explicitly limit generalization; the course does not require three or four projects as an absolute minimum.

Optional work is cut in this order: extra models, CodeQL, extra projects, extra transformations. Never cut label audit, the deterministic-only control, TP retention, or honest failure reporting to make room for optional scale.

## 14. Suggested calendar and report allocation

This is a planning schedule, not a promise of asynchronous execution.

- 22–25 October: baseline/data feasibility and documented design.
- 26 October–4 November: minimum implementation and deterministic tests.
- 5–12 November: freeze and primary controlled evaluation.
- 13–20 November: real-world case studies, ablations, resource/stability analysis.
- 21–27 November: report, figures, and fresh-environment reproduction.
- 28–30 November: artifact/publication checks and submission buffer.

Aim for roughly 8.5–9.5 main-text pages: introduction/related work 1–1.5; preliminaries 1; approach 2; experimental setup 1; results/failure analysis 2–2.5; limitations/conclusion/AI statement 0.75–1. Include all material within the actual course limits, not an unlimited appendix.

Planned result tables (no invented values):

1. Subjects: corpus, revision, cases, positives/negatives/ambiguous, family count, local/cross-function scope, coverage.
2. Main comparison: method, evaluated units, TP, FP, FN, precision, recall, F1, TP retention, FP removal, unknown/failure count.
3. Ablations and pairs: method, semantic family, pair accuracy, transformation consistency, checker rejections, wrongful suppressions.
4. Resources: model ID, uncached calls, input/output tokens, cold latency, wall time, replay time, retries, endpoint failures.
5. Representative cases: target, baseline behavior, model decision, evidence check, correct outcome, root cause, limitation.

Include an actual success, an actual failure, and an example where the LLM or evidence gate does not help. Do not promise those categories are populated before running; report what occurs.

## 15. What Claude should do next

Read the existing project and local course documents. Implement this plan in staged, reviewable changes, beginning with Gates 0 and 1. First produce design, literature, protocol, and feasibility documents. Then implement the minimum complete comparison and tests. Continue with the declared experiments using the configured SoCLaaS client when the prerequisites pass.

Do not infer missing benchmark counts, invent execution logs, fabricate references, relabel cases to favor our system, or claim the student personally performed work done by an assistant. Leave evidence-backed decision points in the design log for Yufan to inspect. Surface substantive scope changes rather than quietly replacing this plan.

## Source register

Primary sources consulted for the plan. URLs are provided for the implementing agent to retrieve the actual documents; pin versions where supplied.

R0. Supplied course specification: `course-project-doc.pdf`, Sections 1–6, especially pp. 1–5.

R1. LLMDFA: Analyzing Dataflow in Code with Large Language Models, NeurIPS 2024; method Section 3.
`https://proceedings.neurips.cc/paper_files/paper/2024/file/ed9dcde1eb9c597f68c1d375bbecf3fc-Paper-Conference.pdf`

R2. IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities, ICLR 2025; method Section 3.
`https://arxiv.org/pdf/2405.17238`

R3. ZeroFalse: Improving Precision in Static Analysis with LLMs, 2025 preprint; Section 3.
`https://arxiv.org/html/2510.02534v1`

R4. Minimizing False Positives in Static Bug Detection via LLM-Enhanced Path Feasibility Analysis, 2025 preprint; Section 3.
`https://arxiv.org/html/2506.10322v1`

R5. Sifting the Noise: A Comparative Study of LLM Agents in Vulnerability False Positive Filtering, 27 June 2026 version; especially Section 5.2.
`https://arxiv.org/html/2601.22952v2`

R6. Finding Vulnerabilities via LLM-Augmented Semantics-Aware Type-Checking (PySeType), 14 August 2026 preprint; Section IV and limitations.
`https://arxiv.org/html/2608.14533v1`

R7. Memoir: Learning, Verifying, and Evolving False-Positive Memories for Static Application Security Testing Tools, 10 August 2026 preprint.
`https://arxiv.org/html/2608.09181v1`

R8. Semgrep taint-analysis documentation; Pro/CE scope and source/sink/sanitizer rules.
`https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview`

R9. Semgrep CLI reference; inspect installed pinned version as well.
`https://docs.semgrep.dev/cli-reference`

R10. OWASP Benchmark for Python official repository, inventory, and labels.
`https://github.com/OWASP-Benchmark/BenchmarkPython`
`https://github.com/OWASP/www-project-benchmark/blob/master/tab_python_test_cases.md`
`https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkPython/main/expectedresults-0.1.csv`

R11. Historical OWASP label/source issue and inspected current case.
`https://github.com/OWASP-Benchmark/BenchmarkPython/issues/1`
`https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkPython/main/testcode/BenchmarkTest00008.py`

R12. An Empirical Study of Vulnerabilities in Python Packages and Their Detection (PyVul), 4 September 2025 preprint; benchmark design and label limitations.
`https://arxiv.org/html/2509.04260v1`
`https://github.com/billquan/PyVul`

R13. Official Python pathname semantics. Resolve documentation for the pinned runtime, not only the moving latest version.
`https://docs.python.org/3/library/os.path.html`

R14. Official Flask API documentation, especially `send_from_directory` and its trusted-directory precondition.
`https://flask.palletsprojects.com/en/stable/api/#flask.send_from_directory`

R15. CodeQL Python path-injection query documentation, optional reference baseline.
`https://codeql.github.com/codeql-query-help/python/py-path-injection/`

R16. Additional related-work scope checks, not implementation dependencies.
`https://arxiv.org/html/2504.16057v5`
`https://arxiv.org/html/2604.06633`
`https://github.com/protectai/vulnhuntr`
