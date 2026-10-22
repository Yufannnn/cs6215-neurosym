# Literature positioning

How each source was inspected:

- **GPT Pro (planning):** read the method sections cited in `docs/plan/PLAN.md` § 3 and source register R1–R16.
- **Claude Code (implementation):** verified each citation's title, authors and year from its arXiv or proceedings landing page on 2026-10-22. It did not re-read the method sections.

The overlap and difference columns describe our design as implemented.

| Work | Version consulted | Relevant mechanism | Overlap with this project | Concrete difference |
|---|---|---|---|---|
| LLMDFA (Wang, Zhang, Su, Xu, Xie, Zhang), NeurIPS 2024 | Proceedings version | LLM extracts sources/sinks, summarizes functions, validates path feasibility with external tools | LLM reasoning about data flow | The LLM never discovers flows: Semgrep's alerts are the only candidates, and flow facts come from our deterministic extractor. No LLM-written code or solver queries |
| IRIS (Li, Dutta, Naik), ICLR 2025; arXiv:2405.17238 | arXiv v3 (Apr 2025) | LLM-inferred taint specifications for CodeQL, then contextual LLM filtering of alerts | Static analyzer + LLM filtering of alerts | Specification is hand-written and frozen; we study only the filtering stage, against a deterministic-only control |
| ZeroFalse (Iranmanesh et al.), arXiv:2510.02534 | v1 (Oct 2025) | Canonicalized SAST alerts enriched with flow context; CWE-specific structured LLM adjudication | Closest: structured evidence + CWE-specific LLM verdicts | Our evidence gate checks the model's cited IDs and claim type against extracted facts (guard dominance, value identity via slice cut, coverage); separate D arm; semantic judgments counted separately |
| LLM4PFA (Du et al.), arXiv:2506.10322 | v1 (Jun 2025) | Iterative interprocedural path-feasibility reasoning with LLM-generated SMT | False-positive reduction through feasibility | Intraprocedural, solver-free, deterministic constant folding / branch pruning |
| Sifting the Noise (Xiong, Zhang), arXiv:2601.22952 | v2 (Jun 2026) | Comparative study of LLM agents for false-positive filtering; measures suppressed true positives | Motivation: TP retention as a first-class metric | Our metrics report FP removal and TP retention together, with paired cluster-bootstrap differences |
| PySeType (Wang, Xu, Asokan), arXiv:2608.14533 | v1 (Aug 2026) | LLM-augmented semantics-aware type checking for Python vulnerabilities | Python neuro-symbolic vulnerability analysis | No type system; warning triage only |
| Memoir (Guan et al.), arXiv:2608.09181 | v1 (Aug 2026) | Learning and verifying reusable false-positive memories for SAST | LLM-based false-positive reduction with verification | No memory, retrieval or learning; one bounded call per alert |
| PyVul (Quan et al.), arXiv:2509.04260 | v1 (Sep 2025) + repo @ 1172bfd1 | Python vulnerability dataset with commit- and function-level records | Real-world subject source | We use commit-level CWE-22 records and our own pinned acquisition; function labels are used only to name targets |

Related tools listed in the plan but not used: MoCQ, Argus, Vulnhuntr. None of their code or prompts was used or adapted.
