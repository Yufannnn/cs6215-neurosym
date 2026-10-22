# Agent instructions

CS6215 individual project: compare a symbolic static-analysis baseline with a self-designed neuro-symbolic analyzer on the same subjects. Course requirements: `docs/course/REQUIREMENTS.md`. Deadline 30 Nov 2026, 23:59 SGT.

## Hard rules

- The neuro-symbolic method must be our own design. Do not use an existing neuro-symbolic analyzer, released tool or prebuilt workflow as the main solution. Prior work goes in related work, with the difference explained.
- Every LLM call goes through `neurosym.llm.LLM` so it is cached and logged. No direct API calls.
- Never print, log or commit the contents of `.env`.
- Record design changes and abandoned attempts in `docs/decisions.md` as they happen. The report needs them.
- Baseline and analyzer must run on the same subjects with the same ground truth.
- Report negative results; never tune on the test subjects.

## Commands

```bash
.venv/bin/pip install -e .              # install
.venv/bin/python scripts/smoke_llm.py   # check SoCLaaS access
```

The report is in `report/` (`latexmk -pdf -outdir=build main.tex`).
