# CS6215 adversarial review

**Verdict: keep the project, but do not submit this version.** This is a substantive implementation with useful, reproducible negative results. Its main weaknesses are analyzer correctness and the interpretation of the evaluation—not insufficient novelty or too few model calls. Those weaknesses affect the two 30% rubric components directly.

**Audit scope.** I read the brief, all seven report pages, the protocol and decision log, the main implementation, tests, and archived results. I reran 26 extractor tests, replayed D/EC on 281 archived evidence records across eight runs, and reproduced the diagnostic score objects and bootstrap intervals exactly. I also reran the diagnostic-label harness and executed seven reviewer-created counterexamples. I did not rerun Semgrep or make new LLM calls; the full 50-test suite could not be certified in this environment. The counterexamples below establish extractor/D/EC failures conditional on an alert at the identified sink, not that Semgrep necessarily reports each new program. The attached evidence package contains the scripts and outputs.

## 1. D's “sound containment” recognizer accepts unsafe containment checks

**Severity:** blocker.

**Location:** `src/neurosym/evidence.py:985–1080`, particularly `_is_containment_atom` at `1049–1066`; `src/neurosym/refine.py:18–19`; `report/sections/conclusion.tex:6,12`.

**Problem:** I reproduced two distinct false suppressions with `facts.complete == true` and `recognizer == "sound_containment"`.

First, the `commonpath` recognizer accepts equality with the candidate rather than requiring equality with the trusted root:

```python
ROOT = '/srv/app/files'

def handler():
    candidate = os.path.abspath(request.args['f'])
    if os.path.commonpath([ROOT, candidate]) != candidate:
        abort(403)
    return os.listdir(candidate)
```

For `f=/srv/app`, the guard passes and the program lists the parent of the allowed directory. D suppresses it. This checks that the candidate contains the root, not that the root contains the candidate.

Second, a normalized candidate checked with `candidate.startswith(root + '/')` is accepted when `root` itself comes from `request.args['dir']`. With `dir=/srv` and `f=/srv/secret.txt`, the operation escapes the intended root and D again suppresses it. The protocol explicitly requires a trusted constant root; the implementation does not enforce that requirement here.

**Fix:** Require the correct root/candidate roles, trusted-root provenance, and the normalization and value-identity preconditions. Until implemented, fail closed on unmatched cases. Remove “sound” and “zero risk” from unqualified conclusions. An acceptable report-only alternative is to retain the frozen implementation as a heuristic and report these counterexamples as limitations; it cannot remain a claimed sound control.

**Re-running needed?** Local regression tests are necessary for a code repair. Re-extract archived examples and compare the actual E inputs before making any API calls. Recompute D offline; replay EC on unchanged E inputs. Only changed E inputs require new E generations. Preserve the frozen results and identify repaired runs as post-review correctness corrections, not untouched original evaluation. S and L need not be rerun when their inputs are unchanged.

## 2. Control-flow handling can turn attacker-controlled values into supposedly safe constants

**Severity:** blocker.

**Location:** `src/neurosym/evidence.py:405–463`; especially loop-`else` handling at `429–431` and `finally` handling at `446–462`; `report/sections/approach.tex:34,46,101`.

**Problem:** Two further complete-but-wrong suppressions reproduce.

```python
def handler():
    name = request.args['f']
    for i in [1]:
        break
    else:
        name = 'ok.txt'
    return open(ROOT + '/' + name)
```

At runtime, `break` skips the `else`; the analysis applies it after joining loop exits. With `f=../../secret.txt`, the program reaches `/srv/secret.txt`, but D declares the sink trusted and suppresses.

The second failure loses a returning path before executing `finally`:

```python
def handler():
    name = 'ok.txt'
    try:
        if request.args['mode']:
            name = request.args['f']
            return 'done'
    finally:
        open(ROOT + '/' + name)
```

With a true `mode` and the same traversal input, the `finally` operation receives attacker data. D again suppresses with complete evidence. These are not hypothetical unsupported constructs: the current implementation accepts them as complete.

**Fix:** The smallest defensible correction is to mark relevant loop-`else` and abrupt-exit-through-`finally` constructs incomplete. Supporting them precisely requires separate normal, break, continue, return, and exception completion states. Do not build that machinery merely to preserve broad scope for this course project.

**Re-running needed?** Add both regressions. Apply the input-difference-based replay procedure in finding 1. A report-only correction can instead disclose these as failures of the frozen analyzer and withdraw soundness claims.

## 3. The aliasing safeguard misses shared objects created without a simple alias assignment

**Severity:** blocker.

**Location:** `src/neurosym/evidence.py:261–264,311–319`; `report/sections/approach.tex:46,101`.

**Problem:** The safeguard catches some `alias = existing_container` assignments but misses both of these forms:

```python
a = b = ['ok.txt']
b.append(request.args['f'])
name = a[-1]
```

```python
inner = ['ok.txt']
outer = [inner]
inner.append(request.args['f'])
name = outer[0][-1]
```

Appending `return open(ROOT + '/' + name)` to either handler produces an escaping access for `../../secret.txt`. Both yield a trusted sink, complete evidence, and D suppression. Thus the statement that unsupported container aliasing makes the record incomplete is materially broader than the implemented check.

Because E receives these same facts, this is not only a defect in the deterministic comparator: it can also give the LLM incorrect assurances.

**Fix:** Conservatively flag chained assignments to mutable objects and nested mutable-object sharing as incomplete. Remove any implication that passing the existing alias regression establishes general alias handling. A heap analysis is unnecessary for this submission.

**Re-running needed?** Add these two regressions. Recompute affected evidence and D, and rerun E only where its supplied input changes. Preserve pre-correction results and record the correction separately.

## 4. EC checks dependency coverage, not the promised identity of the checked and consumed value

**Severity:** major.

**Location:** `src/neurosym/evidence.py:1095–1112,1155–1185`; `src/neurosym/refine.py:55–69`; `docs/protocol.md`, EC gate definition; `report/sections/conclusion.tex:8`.

**Problem:** The report says the gate guarantees the right value and a dominating check. The implementation accepts a guarded ancestor in the sink's dependency graph even when a later transformation destroys confinement:

```python
target = os.path.abspath(os.path.join(ROOT, request.args['f']))
if not target.startswith(ROOT + '/'):
    abort(403)
name = target + '/../../secret.txt'
return open(name)
```

For `f=x`, the eventual path is `/srv/app/secret.txt`. D retains this warning. However, EC accepts a correctly formatted, reviewer-constructed suppression verdict citing the earlier guard, because `target` covers the taint origin in the dependency graph. This is a gate-unit counterexample, not a claim that an evaluated model generated that verdict.

The error is stronger than “the LLM misjudged a nonstandard predicate”: here the predicate on `target` can be correct, but the sink consumes a different value.

**Fix:** Either enforce identity-preserving propagation between guard and sink, or explicitly describe EC as a dependency-consistency filter rather than a checked-value guarantee. Rename “covers every attacker flow” where necessary to distinguish syntactic dependency coverage from semantic preservation of confinement.

**Re-running needed?** Wording-only narrowing requires none. A gate-only correction can replay saved E responses offline. Changing facts supplied to E requires the versioned, input-difference procedure in finding 1.

## 5. The real-world scorer does not establish that a warning detects the actual vulnerability

**Severity:** major.

**Location:** `scripts/realworld_eval.py:3–7,53–71`; `results/realworld.json`; `results/runs/rw-vulnerable/evidence/443ac6cc847354b1.json`.

**Problem:** A target is a set of functions associated with a fixing commit. Any warning anywhere in those functions counts as detecting the target. On the fixed revision, warnings in the same functions are treated as negatives for that defect. Neither inference establishes correspondence to the actual vulnerable source–sink flow.

There is a concrete contamination example: the Whoogle target includes a `flask.send_file(tmp_mem, ...)` warning at line 484, while the archived evidence records `tmp_mem = io.BytesIO()`. That is not a filesystem-path argument. It can still contribute to the target-level “detected/retained” outcome because the scorer checks function membership, not the defect.

The same method could count an unrelated surviving alert as successful retention after the genuine vulnerability warning was suppressed. A security-fixing commit also does not establish that every other alert in its changed functions is false.

**Fix:** Either manually map existing warnings to each documented defect, with file, sink, flow and fix evidence, or rename this section to a **changed-function alert-retention case study**. Under the latter choice, do not call these counts CVE detection, true-positive retention, or fixed-target false positives.

**Re-running needed?** No new model calls are required. Correct the target mappings and rescore saved decisions offline, or narrow the claims without changing the numbers. Any retrospective label adjudication must be identified as such.

## 6. The real-world denominator includes targets the stated analysis was never intended to detect

**Severity:** major.

**Location:** `report/sections/preliminaries.tex:5`; `report/sections/evaluation.tex:118–125`; `report/sections/abstract.tex:11`; `report/sections/conclusion.tex:9`.

**Problem:** The report counts four of six real-world targets as missed and uses that number to support an upstream-bottleneck conclusion. Yet its own case descriptions include Flask-CORS URL matching rather than a filesystem operation, and a Windows-specific validator. The task explicitly uses POSIX filesystem semantics and excludes Windows paths.

An out-of-scope target is not a false negative for the declared task. Mixing applicability failures with genuine in-scope misses makes the baseline look less capable than the chosen specification supports.

**Fix:** Separate screened candidates, applicable targets, baseline-reported targets, and confirmed defect detections. Keep excluded candidates in the screening record, but remove them from the in-scope detection denominator. Together with finding 5, replace the headline “4 of 6 vulnerabilities were lost upstream” with a description of the actual observed coverage limitations.

The documented change from three to four projects is not, by itself, an invalid amendment: the log says it preceded real-world runs. The problem is the applicability criterion and interpretation, not the mere existence of that amendment.

**Re-running needed?** No. Reclassify existing subjects and regenerate counts/text; do not expand the dataset merely to restore the original denominator.

## 7. Several report conclusions directly contradict the saved results

**Severity:** major.

**Location:** `report/sections/evaluation.tex:74,125`; `report/sections/abstract.tex:9–11`; `report/sections/conclusion.tex:6–12`; `report/sections/rq4.tex:12`.

**Problem:** These are factual corrections, not requests for stronger experiments.

The report says D's false-positive removal equals EC's on OWASP. For the primary model, D removes **12/33**, while EC removes **11/33**. For the second model, D removes **12/33**, while EC removes **7/33**. D equals E there, not EC.

The statement that every arm retains findings at both fixed real-world revisions is contradicted by `L_retains_fixed=false` for the covered MLflow target in `results/realworld.json`.

“The gate added nothing measurable” omits its observed cost: it rejected one correct E suppression on primary-model OWASP and five on second-model OWASP. Meanwhile, the conclusion calls the gate “necessary,” although no held-out result demonstrates an improvement in retention from adding it.

“Zero risk,” “guarantees,” and “never safety” are not supported by a finite sample and are directly undermined by findings 1–4. The abstract also reads as though all three corpora were evaluated with both models; the supplied real-world runs use the primary model only.

**Fix:** Rewrite the central conclusion as: **In the frozen runs, D retained all benchmark-labeled true positives; E reduced losses relative to L on the diagnostic suite; EC did not improve measured retention and rejected some correct suppressions. Independent correctness review found additional limitations in D and EC.** Limit model comparisons to the corpora actually evaluated.

**Re-running needed?** None for these factual corrections. Regenerate table-linked statements from saved counts rather than editing them from memory.

## 8. “Before any test data was opened” and “disjoint semantic families” overstate diagnostic independence

**Severity:** major.

**Location:** `report/sections/evaluation.tex:9,20`; `report/sections/approach.tex:94,98`; `data/diagnostics/build.py`; `docs/decisions.md:45`.

**Problem:** The same generator contains both development and held-out diagnostic programs. The decision log explicitly records redesigning the held-out `checked_vs_original` examples after validation. That can be legitimate dataset construction before method evaluation, but it is not accurately described as test programs remaining unseen throughout development.

The family labels are disjoint, but semantic independence is weaker. Development includes `basename` patterns that recur in held-out `named_sanitizer2`, and decode-after-check patterns recur across development `decode_order` and held-out `checked_vs_original`. A test asserting disjoint family strings does not establish disjoint semantic mechanisms.

The OWASP splitter also reads code to compute groups, so the literal claim that no test code was “opened” is too strong even where construction is automated.

**Fix:** Describe the diagnostics as **author-constructed, pre-evaluation-frozen stress tests**, not an independently blind semantic-generalization benchmark. Distinguish dataset construction and label repair from prompt/recognizer tuning and from opening results. Record the actual exposure chronology. Retain the external OWASP evaluation as a separate source of evidence.

I found no basis to accuse the authors of hidden post-freeze model-result tuning. The problem is the stronger wording and the degree of independence being claimed.

**Re-running needed?** No. Do not reshuffle the existing test data and present the new split as untouched. Narrow the claim instead.

## 9. The diagnostic validator cannot establish safe labels from absence of a finite attack witness

**Severity:** major.

**Location:** `src/neurosym/diagnostics.py:129–149`; `report/sections/evaluation.tex:9`; `data/diagnostics/label_validation.csv`.

**Problem:** The validator labels a program vulnerable when a tested input produces an escaping operation; otherwise it returns false, even if execution failed. This supplies positive attack witnesses, but it does not prove that a negative program is safe for all inputs.

I reproduced the advertised 72/72 agreement. However, `numeric_id1_safe` throws an exception in **all 165 executions**: the payload set contains no valid numeric input. The harness therefore agrees with its safe label without exercising its intended successful path. That does not prove the label is wrong; it shows that “every label is validated mechanically” overstates what was established.

**Fix:** Separate “attack witness observed,” “no witness among tested inputs,” and “execution inconclusive.” Give safe fixtures a short static justification under the stated assumptions, and report exceptions rather than treating them as reassuring evidence. Add a benign valid input as a local harness sanity check where all executions fail.

**Re-running needed?** No new LLM calls. Revalidate the small local harness after any repair. Only genuinely changed labels require rescoring; changed test programs must be recorded as corrected fixtures, not silently substituted into the original held-out run.

## 10. OWASP label ambiguities are recorded in the artifact but not adequately integrated into the conclusions

**Severity:** major.

**Location:** `data/adjudications.csv`; `report/sections/evaluation.tex:37–44`; `results/runs/test-owasp-q9b/decisions_L.jsonl`.

**Problem:** Eight official-safe block-list examples are explicitly marked `ambiguous` in the adjudication file. The report nevertheless treats all eight as unqualified false positives when interpreting D and the LLM arms.

This matters to the comparison: the primary-model arms retain all eight, whereas second-model L suppresses seven. Thus some of the second model's apparent additional false-positive removal depends directly on disputed labels. The adjudication itself notes that rejecting `../` still permits bare `..`; whether that establishes an exploitable defect depends on the actual operation and the agreed threat definition. The current record does not resolve that question sufficiently to relabel them automatically.

**Fix:** Preserve the official-label main table, explicitly identify these eight ambiguities, and qualify the metrics as agreement with official labels. Add an offline sensitivity calculation excluding the disputed cases, or state that the affected model comparison is label-sensitive. Do not relabel them based on which arm benefits.

**Re-running needed?** Only offline rescoring of saved decisions. No baseline or model rerun is necessary.

## 11. The described method includes a safe-API recognizer and shared-policy file that the implementation does not actually provide

**Severity:** major.

**Location:** `src/neurosym/evidence.py:1196`; `src/neurosym/refine.py:16–17,51–54`; `report/sections/approach.tex:57,81`; `report/sections/preliminaries.tex:8`; `docs/protocol.md`, shared-policy section.

**Problem:** Every extracted record sets `safe_api` to `[]`. Consequently, the D and EC branches for a documented safe API never activate. The report lists this as an implemented method component, not an unused interface.

The claimed shared `configs/policy.yaml` is also absent from the archive; the supplied code uses rule definitions, extractor constants, and prompt text rather than loading that declared file. This does not itself prove that the arms used inconsistent policies, but it does contradict the description of one declared, consumed policy source.

**Fix:** Describe the method actually evaluated. Mark the standalone safe-API route as unimplemented/unexercised or remove it from the implemented feature list. Document the actual rule, constant, and prompt policy locations. Do not add a new feature now solely to make the old prose true.

**Re-running needed?** None for an accurate description. Implementing a new recognizer or changing policy semantics would be a method change and must not be folded into the frozen main results.

## 12. Several reproducibility claims cannot be checked from the review package

**Severity:** major.

**Location:** `src/neurosym/tables.py:155–175`; `src/neurosym/stability.py:49–59`; `report/sections/ai_usage.tex:15`; `report/sections/approach.tex:100`; `src/neurosym/pipeline.py:54–68`; `scripts/realworld_eval.py:63`.

**Problem:** `results/llm_calls.jsonl` is missing, although the resource-table generator requires it and the whole-project 857-request/1.93M-token totals depend on it. Earlier development runs cited for the p1-to-p2 improvement are also absent. The stability file preserves decisions and freshness flags, but not the underlying raw responses or verdicts; those appear to remain only in the excluded cache. Thus “every model response, prompt, token count and backend fingerprint is stored in the artifact” is not established by this package.

In addition, real-world rescoring reads absolute `/Volumes/Storage/...` paths from archived alerts. The run function permits an existing output directory and overwrites its files, so reproducing a named run can replace the evidence it was intended to verify.

**Fix:** Export sanitized logs and stability request/response records; no API keys or private cache directory need be published. Include cited development summaries or qualify unsupported historical claims. Resolve archived paths relative to the project root, and refuse overwriting frozen run names by default. Make a clear distinction between offline replay and fresh reruns.

A fetch-based artifact need not bundle OWASP or all real-world source snapshots. Likewise, the absence of Git history in this ZIP is not evidence of post-freeze changes, but the final artifact should expose the freeze tag and relevant history for independent verification.

**Re-running needed?** No fresh generations if the local logs/cache still exist. Export and replay them. If they no longer exist, narrow the corresponding reproducibility claims instead of presenting newly generated answers as the originals.

## 13. The baseline explanation wrongly says Semgrep does not reason about values

**Severity:** minor.

**Location:** `report/sections/preliminaries.tex:11`.

**Problem:** The report categorically says Semgrep does not reason about values and therefore a constant overwrite still counts as tainted. Official Semgrep documentation describes constant folding and constant propagation, including Community Edition support. Its documented limitations distinguish lack of path sensitivity and limited aggregate/alias handling from absence of all value reasoning.

This does not invalidate the recorded slice/dictionary failures. It invalidates the explanation offered for why D improves on S.

**Fix:** Replace the categorical statement with the exact observed limitations of the pinned engine/configuration. Attribute specific false positives to their actual program patterns. Describe S consistently as “Semgrep CE 1.182.1 with our frozen custom CWE-22 taint rule,” not a blanket statement about all Semgrep capabilities.

**Re-running needed?** None for the wording correction. Existing development evidence should support the particular limitations retained in the text.

External verification: Semgrep official documentation, [Constant propagation](https://docs.semgrep.dev/writing-rules/data-flow/constant-propagation) and [Dataflow analysis engine overview](https://docs.semgrep.dev/writing-rules/data-flow/data-flow-overview), checked 23 October 2026.

## 14. Bootstrap intervals and two-model comparisons must not be interpreted as safety or generalization guarantees

**Severity:** minor.

**Location:** `src/neurosym/scoring.py:30–66`; `report/sections/evaluation.tex:50`; `report/sections/conclusion.tex:7,12`; `report/sections/rq4.tex:12`.

**Problem:** The bootstrap implementation correctly preserves cluster multiplicity, and the diagnostic score objects reproduce exactly. The concern is interpretation, not a demonstrated arithmetic bug.

Where no true-positive loss occurs in the observed sample, resampling it can produce a degenerate `[1.00, 1.00]` retention interval. This does not establish zero future loss. The diagnostics contain only 12 constructed semantic families; their resampling intervals describe variability within that suite rather than a representative population of Python security patterns.

Likewise, “the representation mattered more than the model” is broader than this two-configuration comparison supports. L-to-E changes the fact representation, the explicit obligations, and supplied analysis conclusions together. The model comparison also does not isolate model size from model family, serving configuration, or reasoning behavior.

**Fix:** Keep the existing intervals, give the raw denominators, and explicitly describe the degenerate-boundary limitation. Prefer “the evidence-guided prompting configuration reduced losses in this diagnostic suite” over claims about universal representation superiority or a causal model-size effect.

**Re-running needed?** None. Do not add a factorial study merely to justify wording that can be narrowed.

## 15. Failure accounting and resource terminology omit distinctions the protocol promised

**Severity:** minor.

**Location:** `report/sections/rq4.tex:18–19`; `src/neurosym/triage.py:87–112`; `results/tables/resources.md`; held-out `decisions_L.jsonl` and `decisions_E.jsonl` files.

**Problem:** The report does not clearly summarize invalid outputs and unsupported evidence, although these affect retention through fallback. Primary-model diagnostics contain three final invalid-JSON L outcomes and one E `no_evidence` outcome. Second-model diagnostics contain one final invalid-JSON E outcome and one `no_evidence` outcome. These should not be read as successful model reasoning.

“Logical calls” also conflates units with successful completion requests including schema repair: primary-model OWASP has 68 alerts × two LLM arms = 136 first attempts, but the table lists 137 because it includes a repair. Finally, “171 transport retries ... none changed an answer” is not established by the logs: failed attempts generally do not supply an answer against which to compare the successful one.

**Fix:** Add a compact status summary from existing decisions and distinguish logical triage jobs, schema-repair completions, transport attempts, and cache hits. Replace the retry statement with “transport retries were not conditioned on answer content; schema repair was limited to the declared retry.” Preserve conservative fallback in the main scores, but make its contribution visible.

**Re-running needed?** Offline aggregation only. No additional experiments are justified for this correction.
