# CS6215 second adversarial review — v2

**Reviewed package:** `cs6215-neurosym-review-v2-2026-10-25.zip`  
**Review date:** 25 October 2026  
**Basis:** the supplied `REVIEW_BRIEF.md`, eight-page report and source, implementation, archived experiments, response cache, Git bundle, first-review response, and the original CS6215 project handout.

## Verdict

**Substantially improved, but not yet ready for final submission.** The first review was acted on in a meaningful way. The numerical results are much more auditable, the real-world evaluation is substantially more careful, and the report now presents several genuine negative findings. The original regression witnesses are handled. This is not a reason to restart, add models, or acquire a larger benchmark.

However, the corrected extractor still suppresses six newly constructed unsafe programs while marking their evidence complete. These arise from four specific implementation defects. The supplied regression file demonstrates all six without opening real files. They are conditional-on-alert tests of the refinement stage; I did not establish that Semgrep reports the new examples. The findings do not invalidate the arithmetic of the existing benchmark tables. They invalidate broad assurances that the implemented recognizers prove safety for the constructs they accept.

My approximate coursework assessment is **around 80/100**, up from the earlier provisional 68. This is a reviewer judgment, not a prediction of the instructor's marking. Targeted corrections could plausibly put the submission in the mid-to-high 80s. No increase in experimental scale is needed to justify that improvement.

## What I verified, and what I did not

### Direct checks

- **56 existing extractor and review-regression tests passed** against the unchanged project source.
- **77 tests passed** in an expanded offline run, using an audit-only, fail-closed SDK import stand-in. The additional tests exercise project logic and fake-client behavior, not a real installed OpenAI SDK. Four tests requiring Semgrep or the absent OWASP source were not certified. This is not a claim that the full 81-test installation passed.
- Recomputed **D and EC decisions for 569 archived alerts across 16 run directories**, using stored evidence and stored E verdicts: no disagreements.
- Recomputed both diagnostic score objects, **including their cluster-bootstrap confidence intervals**, exactly.
- Replayed all diagnostic L/E jobs for both models from the supplied cache: **168 logical jobs, 171 cached completion requests**, no decision, verdict, or status differences. These were triage replays on archived baseline alerts, not new Semgrep runs.
- Checked all **444 archived held-out completion records** against their cache entries: none missing and no content differences.
- Parsed the **180 exported stability responses** and reproduced their decisions. L had no decision flips; E and EC had two flipped replicates out of 90 on one alert.
- Verified the resource arithmetic: **874 uncached requests, 2,003,573 tokens**, including development and correction runs. The held-out transport-retry total is 171.
- Reran the diagnostic witness harness: 72 programs, 36 with attack witnesses and 36 with no witness in the tested inputs. The latter remains finite testing, not proof of safety.
- Inspected the supplied Git history. The protocol freeze precedes the recorded test-result commits; the first correction is separately tagged. I found no basis to allege hidden post-freeze result tuning.

### The “220 unchanged records” claim

There are **220 held-out alert slots across the four model/corpus runs**, but **218 actual evidence JSON records**. The same unsupported diagnostic alert has no record in each model run. All 218 stored records are byte-identical between the frozen and first-correction directories, and the two missing-record statuses remain unchanged. All saved decisions and scores match.

I independently re-extracted all diagnostic alert slots from the supplied source: no evidence or E-input changes. I also re-extracted the real-world snapshots: all 16 original records changed, as documented, and all 16 current records match the corrected archive. The recorded real-world decisions remain unchanged.

**The OWASP source is deliberately absent from the package.** I verified agreement of its stored original/corrected evidence and cache records, but could not independently repeat its extraction or baseline run in this environment. The report should say “220 alert slots, including two unsupported slots” rather than imply 220 concrete records or 220 independent programs.

### Boundaries

I did not run Semgrep, make fresh model calls, certify the real SDK integration, or complete a fresh dependency installation. Missing network access in the review environment is not itself a project defect. The README failures below are separate, reproducible control-flow problems in its instructions.

For the new witnesses, request input `../../secret.txt` reaches a stubbed filesystem operation whose normalized path is `/srv/secret.txt`, outside the stated `/srv/app/files` root. No sensitive file is read. EC outcomes on the two normalization witnesses use **reviewer-constructed verdicts**, not observed model responses.

## Rubric assessment

The handout gives 30% each to method design/implementation and comparative evaluation. It explicitly accepts negative findings and does not require outperforming the baseline. Consequently, D matching E is not a reason to mark the neuro-symbolic project as failed.

| Component | Weight | Provisional assessment | Clearly above the bar? |
|---|---:|---:|---|
| Preliminaries | 10 | 9 | Yes. Task, baseline configuration, scope, and recall limits are clear. Qualify the remaining safety language. |
| Evaluation setting | 10 | 8 | Yes for coursework. Development/test exposure, author-constructed diagnostics, and applicability are now much more candid. One real-world label explanation remains overstated. |
| Neuro-symbolic design and implementation | 30 | 23 | Substantial and distinct from adopting an existing analyzer. Correctness is not yet strong enough for a high-confidence final submission. |
| Comparative evaluation and findings | 30 | 25 | Yes. Five useful controls, retention/removal accounting, failure analysis, stability, and reproducible negative results are strengths. |
| Writing and AI Usage Statement | 10 | 8 | Generally above the bar, but the disclosure is visibly unfinished and several conclusions still overreach. |
| Artifact and reproducibility | 10 | 7 | Strong archived evidence; not yet a complete hand-in because the current replay recipe fails and public accessibility is unverified. |
| **Total** | **100** | **80** | **A stronger project than v1, with bounded remaining corrections.** |

These allocations are illustrative rather than calibrated grading predictions. The report meets the expected scale and the supplied eight-page layout is within the handout's length allowance. No additional GPU use, model training, or large-scale study is indicated.

# Ranked findings

## 1. Keyword-based mutations lose attacker data

**Severity:** major.  
**Location:** `src/neurosym/evidence.py:595–632,649–672`, especially dispatch at line 627 and mutation handling at lines 650–671.

**Problem.** The call handler evaluates both positional and keyword arguments, but the local-method analysis receives only positional arguments. The mutation and dependency logic then ignores keyword values. This produces a complete, trusted sink for:

```python
def handler():
    cfg = {'f': 'ok.txt'}
    cfg.update(f=request.args['f'])
    name = cfg['f']
    return open(ROOT + '/' + name)
```

The runtime dictionary contains attacker input. D returns `suppress`, with `constant_or_overwritten_value` and `facts.complete == True`. The supplied test confirms the escaping path first, then fails the expected-retention assertion.

**Fix.** Carry keyword names and abstract values into mutation semantics and reaching dependencies. Handle `dict.update` keyword assignments explicitly, or mark the affected record incomplete when a keyword mutation is not modeled. An unmodeled mutation must not silently preserve a trusted receiver. A conservative fallback is sufficient; this does not require general heap analysis.

**Re-run needed?** Add this regression, create a separately versioned correction, and use the selective replay procedure below. No reason to rerun S or L when their inputs are unchanged.

## 2. Boolean expressions have the wrong value and side-effect semantics

**Severity:** major.  
**Location:** `src/neurosym/evidence.py:555–557,823–825`.

**Problem.** Two distinct errors share this implementation. `_boolop` turns values into booleans with `all`/`any`, and the evaluator eagerly evaluates every operand before computing the result.

The first witness exploits the wrong result value:

```python
def handler():
    mode = 'upload' or 'fallback'
    name = request.args['f']
    if mode != 'upload':
        name = 'ok.txt'
    return open(ROOT + '/' + name)
```

Execution leaves `mode` equal to `'upload'`, so the overwrite does not occur. The analyzer instead computes `True`, takes the overwrite, and suppresses.

The second exploits evaluation of an operand that is skipped at runtime:

```python
def handler():
    names = [request.args['f']]
    False and names.append('ok.txt')
    name = names[-1]
    return open(ROOT + '/' + name)
```

The runtime never appends the safe name; the analysis does. Both warnings are incorrectly suppressed with complete evidence.

**Fix.** Implement operand-valued, short-circuit evaluation, including conditional state effects. When the controlling truth value is unknown, conservatively join feasible effects or mark the relevant case incomplete. A simpler supported-subset restriction is acceptable, but continuing to mark these cases complete is not.

**Re-run needed?** Two regressions and versioned selective replay. These are implementation-correctness repairs, not opportunities to tune against test results.

## 3. Dictionary lookup treats duplicate keys as first-wins

**Severity:** major.  
**Location:** `src/neurosym/evidence.py:568–579,863–869`; also align the dictionary `.get` path around lines 948–954.

**Problem.** Literal construction preserves duplicate entries and lookup returns the first matching entry. The runtime retains the later value for an equal key:

```python
def handler():
    cfg = {'f': 'ok.txt', 'f': request.args['f']}
    name = cfg['f']
    return open(ROOT + '/' + name)
```

D sees the safe entry and suppresses with complete evidence; the execution witness reaches the attacker-controlled path.

**Fix.** Construct dictionaries using sequential overwrite semantics for provably equal keys. Handle uncertain collisions conservatively and apply the same interpretation to indexing and `.get`. Marking duplicate-key literals incomplete is an acceptable bounded correction if precise support is unnecessary.

**Re-run needed?** Add the regression and use versioned selective replay. Do not expand into unrelated container features.

## 4. A familiar function name is mistaken for proven normalization

**Severity:** major.  
**Location:** `src/neurosym/evidence.py:211–220,604–611,1168–1174`; `src/neurosym/refine.py:66–68`.

**Problem.** `_is_normalized` accepts a name resolved through stale import information, or any method whose attribute name is `resolve`, without establishing that the executed operation actually normalizes a path.

One witness shadows an imported normalizer:

```python
from os.path import abspath

def abspath(value):
    return value

def handler():
    candidate = abspath(ROOT + '/' + request.args['f'])
    if not candidate.startswith(ROOT + '/'):
        abort(403)
    return open(candidate)
```

The other uses a custom class whose `resolve()` simply returns its input. With `../../secret.txt`, both unnormalized strings pass the prefix check. D marks both as `sound_containment` and suppresses.

A reviewer-constructed suppression verdict citing the guard also passes EC as `trusted_contract_matched` for both witnesses. That tests the gate's acceptance rule; it is not evidence that the evaluated LLM produced such a verdict.

**Fix.** Establish an unshadowed normalizer binding, and accept `.resolve()` as normalization only with adequate receiver provenance. When either fact is unknown, do not award a trusted containment contract. It is sufficient to decline this recognizer; whole-program type inference is unnecessary.

**Re-run needed?** Add both regressions and use versioned selective replay. Changing the shared evidence can affect D, E, and EC; assess that through actual input differences.

## 5. The fixed Whoogle explanation still assumes path confinement that its guard does not establish

**Severity:** major for ground-truth interpretation.  
**Location:** `data/realworld/alert_adjudication.csv:10–12`; `data/realworld/snapshots/benbusby__whoogle-search/3a2e0b262e/fixed/app/routes.py:426–438,449–454`.

**Problem.** The revised per-warning mapping is a genuine improvement over v1. However, the fixed-site explanation says that no file outside `CONFIG_PATH` is reachable after normalization and allow-listing. The guard accepts `..`:

```python
name = os.path.normpath('..')
# '..' matches: ^[A-Za-z0-9_.+-]+$
config_pkl = os.path.join(CONFIG_PATH, name)
```

The normalized joined path is the parent of the configured root. The code then performs an existence check and attempts an open on that path. Directory opening may fail, so this is **not** a demonstrated arbitrary-file-read exploit or a new CVE claim. It nevertheless does not justify the stated confinement explanation, particularly because the report's task includes outside-root existence probing.

**Fix.** Keep the neutral `fixed_defect_site` role, but replace the safety assurance with a precise description of the fix and its residual `..` behavior. The current report already avoids treating an entire fixed repository as safe; make the supporting annotation equally careful. Do not invent a stronger vulnerability label from this local check either.

**Re-run needed?** No new model calls. Amend annotations and related prose; rescore only if a metric actually uses the disputed site as a safe negative. This need not change the neutral site-retention table.

## 6. The current reproduction commands do not replay the corrected project

**Severity:** major.  
**Location:** `REVIEW_BRIEF.md:35–42`; `README.md:55–89`; `src/neurosym/pipeline.py:42–63`; `src/neurosym/cli.py:14–24,43–54`.

**Problem.** There are three independent instruction problems.

The supplied worktree directory has no `.git`, so its test-data freeze guard cannot resolve the required tag. Cloning the supplied bundle fixes that, but its HEAD is the corrected implementation. A default run checks against `protocol-freeze` and is correctly rejected because relevant files changed. I reproduced this rejection and verified that the `review-correction-1` guard passes.

Finally, the README tells a reader to use the already archived run names. The new overwrite protection correctly refuses those names. Adding `--offline` does not bypass any of these checks, and it still runs the baseline, so Semgrep remains required for a full pipeline replay.

**Fix.** Document original-version and corrected-version replay separately. For a corrected replay, clone the bundle/repository with its tags, extract the cache, use `--correction`, and choose a fresh `corr-` name. For example, after dependencies and cache setup:

```bash
python -m neurosym.cli run --correction \
  --subjects diag:test --name corr-replay-diag-v2 \
  --model qwen3-coder-next --offline
```

This is the control-flow correction for the reviewed version, not a claim that I executed this entire command successfully with Semgrep. Once a second correction is made, document its corresponding version/tag mechanism too. Preserve overwrite protection and freeze checks. A separate saved-results rescore command would make the simplest audit independent of both API access and Semgrep.

**Re-run needed?** Validate the documented clean-clone recipe. No fresh model generation or new scientific experiment is required to repair documentation and replay routing.

## 7. The final disclosure and public-artifact requirement are still unfinished

**Severity:** blocker for final submission, not an allegation of misconduct.  
**Location:** `report/sections/ai_usage.tex:6,9,12`; artifact address in `report/main.tex:29`; final-publication steps in `HANDOFF.md`.

**Problem.** Three literal `[confirm]` placeholders are visible in the PDF. They follow claims about the student's choice of direction, review of design decisions, and review/editing of the report. Those are facts about human involvement, not text that an assistant can verify or silently assume.

The report now gives a repository address, but an authenticated repository-metadata check returned 404. That can reflect privacy, permissions, or an incorrect address; it does not prove the repository does not exist. Public accessibility is therefore unverified, and the handoff still identifies publication as unfinished. The course requires a publicly accessible repository linked from the report.

**Fix.** The student should replace each placeholder with a truthful description of what they actually did, editing the surrounding claim as needed. Merely deleting the marker is not enough if the sentence is inaccurate. Before submission, verify the artifact link without authentication and publish the approved final artifact and tags. Do not expose credentials or unnecessary personal records.

**Re-run needed?** No experiments. Rebuild the PDF and verify the public artifact. Do not publish automatically as part of a code-repair agent's work without the student's authorization.

## 8. Some remaining claims confuse retention, implementation assumptions, and guarantees

**Severity:** major for precision of conclusions.  
**Location:** `report/sections/abstract.tex:3`; `approach.tex:51,54,72,84`; `conclusion.tex:5–9`.

**Problem.** Several narrowly repairable statements remain.

“Keeping every labelled vulnerability” should mean **retaining every baseline-detected benchmark positive**. On OWASP, the baseline detects 35 of 58 positives; the final recall is still 60.3%, not 100%. On diagnostics it detects 23 of 24.

The stated four assumptions do not make the implementation's proofs valid. The keyword, Boolean, and dictionary witnesses use declared sources and ordinary modeled operations without symlinks or hidden library sources. They show that `complete` records can still be wrong. The appropriate statement is that the recognizers are a bounded implementation whose correctness is empirically tested, not established by listing assumptions.

“An incomplete record can never justify a suppression” should be scoped to **D and EC's implemented checks**. E is prompted to follow obligations but does not receive the same deterministic gate. No incomplete-record E suppression was observed in the archived runs; absence in these runs is not a program invariant.

The gate's “every tainted flow” guarantee is at most about the **extracted dependency graph**, conditional on extractor correctness. It is not a guarantee about all executions of the original program.

The claim that “an LLM is most useful” for nonstandard checks is broader than the experiments establish. Report where E had additional useful suppressions in these diagnostics instead of asserting its universally best role.

The abstract also ties two distinct facts together causally: EC failed to catch wrong suppressions, and EC rejected correct suppressions. The second-model correct suppressions were rejected for citation-format errors, not because structural checking inherently could not establish confinement. State the observed reasons separately.

**Fix.** Narrow these statements. Suggested terminology: “recognized containment pattern,” “no additional false negatives on the evaluated benchmark,” “retention among baseline-detected positives,” and “consistency with extracted dependencies.” Do not remove the substantive conclusion that D was a strong control.

Also replace “all 220 evidence records” with “all 220 alert slots, comprising 218 records and two unsupported slots,” and “before any test data was seen” with the actual claim supported by the history, such as “before comparative test runs.” Dataset construction was not blind to its own programs.

**Re-run needed?** None for wording corrections. The four implementation fixes must follow the versioned replay procedure, but broader experiments are not necessary to justify appropriately bounded claims.

## 9. The prose rewrite has produced long, overloaded sentences

**Severity:** minor.  
**Location:** `report/sections/approach.tex:42`; `evaluation.tex:24`; `rq4.tex:10`; `abstract.tex:1`.

**Problem.** Avoiding semicolons, colons, dashes, asides, and lists does not itself improve technical writing. Several paragraphs now join distinct claims through long chains of commas and conjunctions. The statement-semantics paragraph moves through constant folding, branches, loop convergence, abrupt exits, exceptions, non-returning calls, and unknown functions in very little visual structure. The resource paragraph combines latency, rate limiting, retry policy, request units, total budget, CPU cost, and service charging.

I cannot infer authorship from these stylistic features, and the report should not be optimized around an AI-detector assumption. The issue is reader effort and technical precision.

**Fix.** Use shorter sentences and normal technical punctuation. For example:

> Statements are analyzed in source order. Constant folding handles the supported string, path, and container operations. Conditions with known truth values prune infeasible branches. Loops use at most five iterations before widening; a failure to converge marks the record incomplete.

Describe abrupt exits and exceptions separately. Split cost into request accounting, latency, and total budget. In the abstract, state the question and headline result before enumerating every arm and dataset.

**Re-run needed?** No experiments. Rebuild the report and inspect page breaks, figure placement, and numerical references after editing.

# How to frame the main result against the rubric

**Lead with the assigned comparison, then immediately give the deterministic control.** Do not lead only with D, and do not hide D to make the LLM look necessary.

The verified primary OWASP counts are:

| Configuration | True positives | False positives | Precision | Recall |
|---|---:|---:|---:|---:|
| S | 35 | 33 | 51.5% | 60.3% |
| D | 35 | 21 | 62.5% | 60.3% |
| E | 35 | 21 | 62.5% | 60.3% |
| EC | 35 | 22 | 61.4% | 60.3% |

Thus E removes 12 of 33 baseline false warnings and retains all 35 baseline-detected positives. D achieves exactly the same result. The supported conclusion is that evidence-guided triage improves this baseline's precision, but this benchmark does not demonstrate a benefit from adding the LLM beyond the deterministic refinement.

On the primary-model diagnostic suite, L loses seven baseline-detected positives while E loses two, with both removing 15 of 19 false warnings. This is useful evidence for the structured **configuration**, not a clean isolated causal estimate of representation alone. With the smaller model, E retains all 23 baseline-detected positives, including two through conservative fallback, and removes 12 false warnings. D removes 13 while retaining the same 23.

EC provides a defensible negative result: it prevents none of the observed wrong suppressions, while rejecting one and five correct OWASP suppressions for the two models. Its failure and costs belong in the report, not behind another round of prompt optimization.

A suitable replacement opening for the result paragraph is:

> On 134 held-out OWASP cases, evidence-guided triage removed 12 of 33 baseline false warnings and retained all 35 baseline-detected vulnerabilities. Precision increased from 51.5% to 62.5%, with recall unchanged at 60.3%. Our deterministic control achieved the same result, so this benchmark does not establish an incremental benefit from the LLM. On author-constructed diagnostic pairs, structured evidence reduced the primary model's wrongful suppressions from seven to two at the same false-positive removal. The additional evidence gate prevented none of the observed wrongful suppressions and rejected some correct ones.

Follow that paragraph with the extractor limitations and the separately versioned corrections. These are measured course-project findings; they need not be advertised as an ICSE-level new analyzer or a general safety result.

# Correction and rerun discipline

For findings 1–4, preserve all original and first-correction results. Add the six reviewer tests to the regression suite and implement either correct semantics or explicit conservative unsupported-case handling. Record a new correction version/tag.

Re-extract evidence at every archived baseline alert and compare the exact input supplied to E, not just a summary flag. Recompute D locally. Replay EC over stored E replies when their original input is unchanged. Generate a new E reply only for an alert whose supplied input changes, recording that it belongs to the correction run. If E inputs do not change, cached replies remain valid. S and L need no rerun unless their own input, policy, engine, or context changes.

Keep these as post-review correctness corrections, not a newly untouched test study. If no held-out decisions change, report that useful fact alongside the new regressions. It does not prove general correctness, and there is no need to engineer a changed headline number.

# Priority for the next revision

The highest substantive value is to repair the four demonstrated semantic errors and remove unsupported proof language. The scope can remain small: returning “incomplete/retain” is acceptable where implementing correct semantics would widen the project.

Next, correct the Whoogle annotation and the main-result framing. These mostly need prose or offline rescoring, not additional API expenditure. Finalize the truthful AI disclosure and publicly accessible artifact before hand-in. Repair the replay recipe, then shorten the overloaded prose.

**Do not add another model, enlarge the benchmark, replace the project topic, or begin a third literature-survey cycle.** The work already contains enough comparative analysis for CS6215. Its remaining grade gains come from correctness, defensible interpretation, and making the artifact straightforward to inspect.

## Evidence supplied with this review

`CS6215_V2_Review_Evidence.zip` contains the six executable regression cases, their extracted records and safe runtime witnesses, the failing-regression output, offline audit results, existing-test outputs, and a readme explaining the limits and rerun commands. It contains no API credentials or model cache.
