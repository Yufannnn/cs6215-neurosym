# CS6215 course project: requirements

Source: [project handout](source/course-project-doc.pdf) and [tutorial slides](source/course-project-tutorial.pdf), instructor Chengpeng Wang (wangcp@comp.nus.edu.sg). Summarised 22 Oct 2026.

**Deadline: 23:59 SGT, 30 November 2026.** Individual. No oral presentation.

## Task

Pick a static-analysis task. Run an existing **symbolic baseline** on it, build **your own neuro-symbolic analyzer** for the same task, evaluate both on the same subjects, and explain what the comparison shows.

- Static-analysis topics need no approval. Testing or dynamic-analysis topics need instructor approval first, via a proposal of at most three paragraphs: idea, motivation and relevance, feasibility, baseline.
- LLM APIs and agent harnesses (Codex, Claude Code, OpenHands, SoCLaaS) are allowed as infrastructure, but the method (workflow, prompts, skills, tool integration) must be self-designed.
- **Not allowed as the main solution:** existing neuro-symbolic analyzers from papers, released tools or prebuilt workflows. They may be cited as related work. Disclose any inspiration and explain how the method differs.

## Example baselines (not exhaustive)

| Task | Baseline | Venue |
|---|---|---|
| Indirect calls / call graphs | KallGraph | S&P 2025 |
| Pointer analysis, DB-backed apps | Database-aware pointer analysis | PLDI 2025 |
| Android taint | FlowDroid | PLDI 2014 |
| Java analyses | Tai-e (state the analysis and config) | ISSTA 2023 |
| Use-after-free | Spatio-temporal context reduction | ICSE 2018 |

Recent papers (past 5 years) with runnable tools and datasets are preferred. Run the baseline on a small sample before committing.

## Evaluation

- Subjects: benchmarks, datasets from prior work, or real programs. The baseline must run on them. Three or four real-world projects is enough when tokens are limited.
- Fair setup with stated criteria. Report aggregate numbers **and** representative successes and failures, false positives and false negatives, unexpected behaviour, negative results and failed attempts.
- Report the resource and token budget and how it limited the scope.
- A hybrid or improved solution is optional. Beating the baseline is not required.

## Report

- English PDF, ACM `\documentclass[sigconf]{acmart}`, ICSE 2026 Research Track style.
- 6–10 pages of main text, including figures, tables, appendices and the AI Usage Statement, plus at most one page of references.
- Include name, NUS student ID and the public repo link.
- Structure: Abstract, Introduction, Preliminaries (problem and baseline, in your own words), Approach (own design and iterations, including abandoned ones), Evaluation, optional Extensions, Conclusion, **AI Usage Statement** (what was AI-assisted, how, and what the student decided).

## Artifact

A public repo with a detailed root `README.md`: layout, environment, dependencies, steps to reproduce. It contains baseline links, the implementation, prompts, skills, harness, configs, subjects, evaluation scripts, and raw and processed data where manageable. Ideally an agent (Codex or Claude Code) can reproduce the results from it.

## Grading

| Criterion | Weight |
|---|---|
| Preliminaries | 10% |
| Evaluation setting | 10% |
| Neuro-symbolic method design and implementation | 30% |
| Comparative evaluation and findings | 30% |
| Writing quality, including AI Usage Statement | 10% |
| Artifact and reproducibility | 10% |

Grades reward method and experimental design, not scale or token spend.

## Resources

- SoCLaaS: free OpenAI-compatible API to open-weight models, no quota. Key from https://soclaas-portal.comp.nus.edu.sg, NUS network or VPN, setup guide at https://dochub.comp.nus.edu.sg/cf/guides/soclaas/start. Record the model and configuration used.
- ChatGPT@NUS via NUS SSO.
