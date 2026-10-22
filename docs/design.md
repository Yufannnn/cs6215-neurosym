# Design

Full description: report § 3 (`report/sections/approach.tex`). Frozen parameters: `docs/protocol.md`. History: `docs/decisions.md`.

## Task and threat model

Python CWE-22 warning refinement under POSIX semantics. The attacker controls Flask request data and three benchmark helper getters; module constants are trusted. Out of scope: symlinks, races and Windows paths. The analysis is intraprocedural: the function that contains the sink.

## Pipeline

1. **S:** the frozen Semgrep CE taint rule produces alerts `A`.
2. **Evidence extraction** (`src/neurosym/evidence.py`). For each alert, an abstract interpretation of the enclosing function produces:
   - values: concrete constants (including lists, dicts and paths) plus TRUSTED, UNKNOWN and TAINT;
   - constant-folded `if`/`match` with pruning;
   - loops to a fixpoint (5 rounds, then widen and mark incomplete); `break`/`continue` exits joined;
   - `try` handler entry = join of prefix states; non-returning calls end paths;
   - container aliasing marks the record incomplete;
   - guard coverage by a slice cut: no tainted origin reachable without crossing the guarded definitions.
3. **D:** suppress only if the record is complete and one holds: the sink is unreachable, the sink value is constant or trusted, a safe API applies, or there is sound containment.
4. **L:** LLM over the function source only.
5. **E:** LLM over the source, a fact digest and the full EvidenceRecord, with four obligations.
6. **EC:** E's responses replayed through the gate: schema, cited IDs exist, file hash, record complete, and the claim matches the facts. A guard claim needs a dominating guard that constrains the sink value and covers every tainted flow. Non-sound guards are logged as `semantic_judgment_remaining`.

## Supported syntax

Assign, AnnAssign, AugAssign, Expr, If, Match (literal, or-patterns, wildcard, capture), For and While (fixpoint), Try, With, Return, Raise, Break, Continue, Import.

Unsupported constructs mark the record incomplete: global, nonlocal, del, exec, eval, getattr, setattr, comprehensions, lambdas, walrus, starred expressions and container aliasing.

## Claims and their limits

- `R ⊆ A`, so no arm can exceed S's recall.
- A passed gate is not a proof of safety. `semantic_judgment_remaining` suppressions rest on the model's judgment.
- D's recognizers are sound only for the supported subset, under the stated threat model and lexical POSIX semantics.

## Originality boundary

All code, prompts, the rule and the diagnostics were written for this project. The ideas of LLM triage and structured evidence are not new (`docs/literature.md`). Our specific choices are the D/EC boundary, slice-cut coverage, the EC claim–fact matching, the diagnostic pairs validated by execution, and the retention-first evaluation.
