# Review of PLAN.md (22 Oct 2026)

Review of GPT Pro's plan against the Gate 0–1 findings. All points were resolved in `docs/protocol.md`; reasoning is in `docs/decisions.md`.

1. **D vs EC could predetermine the result.** Both share the extractor. If D's recognizers match the gate's acceptance conditions, EC cannot beat D. Resolved: fixed boundary (D = closed provable set; gate = structural checks; non-standard guard semantics = logged LLM judgment).
2. **Ceiling risk.** A strong policy (helper contracts, dead-branch idioms) leaves few false positives to filter, and D may remove most of the rest. That would be a legitimate finding, and the diagnostic pairs then carry the LLM question. The policy is frozen before test.
3. **Real-world part may be empty.** The filter cannot recover targets S misses, and Semgrep CE is intraprocedural. Resolved: report coverage of every target, and measure retention only on S-reported targets.
4. **No OWASP development split.** Developing the rule blind means guessing idioms. Resolved: a seeded, family-grouped split of about 30 development cases.
5. **Circular diagnostic labels.** The author writes both the method and the tests. Mitigated by building the development and held-out sets separately from independent reference patterns, with mechanical label validation.
6. **Small samples.** After template de-duplication, differences of a few cases are noise. Resolved: cluster bootstrap plus raw counts; no significance claims from tiny samples.
