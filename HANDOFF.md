# Handoff (2026-10-22)

State of the CS6215 project for continuing on another machine. Read with `README.md`, `CLAUDE.md` and `docs/decisions.md`.

## Status

- **Experiments complete:** OWASP test, held-out diagnostic pairs, both models, stability, real-world.
- **Protocol:** frozen at tag `protocol-freeze`, and the frozen files are unchanged since.
- **Report** (`report/`): 7 pages, ACM sigconf, no overfull boxes. Build with `latexmk -pdf -outdir=build main.tex`.
- **Tests:** 50/50 pass. A fresh-clone offline replay reproduced the held-out decisions exactly.
- **Review:** a package was sent to GPT Pro (`REVIEW_BRIEF.md` lists what it was asked to check). Its findings are not yet applied.

## Open items

1. Apply GPT Pro's review findings. Narrow claims rather than add scope. Do not re-run held-out data unless a finding requires it, and record any such re-run in `docs/decisions.md`.
2. Make the repository public, put its URL in place of `ARTIFACT_URL` in `report/main.tex`, and rebuild. Before going public, delete the `llm-cache-2026-10-22` release; see the cache note below.
3. Yufan edits the three `[confirm]` sentences in `report/sections/ai_usage.tex`.
4. Deadline: 30 Nov 2026, 23:59 SGT. Submit the PDF with the repo link.

## Setting up on a new machine

1. Follow `README.md` § Setup: venv, `pip install -e . semgrep==1.182.1 pytest`, and the three pinned `git clone`s into `data/downloads/`.
2. Put the SoCLaaS key in `.env` (not in git). The API needs the NUS network or VPN.
3. **Response cache (optional, for `--offline` replay):** `gh release download llm-cache-2026-10-22 -p llm_cache.tar.gz && tar xzf llm_cache.tar.gz -C results/`.
4. `python -m pytest -q tests`, then e.g. `python -m neurosym.cli run --subjects diag:test --name replay --offline`.

## Rules

- Never print or commit `.env`.
- All LLM calls go through `neurosym.llm.LLM`, on SoCLaaS only. Do not use paid APIs or the Claude subscription for experiments.
- The frozen paths are listed in `src/neurosym/pipeline.py::FROZEN_PATHS`. Changing them invalidates test runs.
