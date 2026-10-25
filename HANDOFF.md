# Handoff (updated 2026-10-25)

State of the CS6215 project for continuing on another machine. Read with `README.md`, `CLAUDE.md` and `docs/decisions.md`.

## Status

- **Experiments complete:** OWASP test, held-out diagnostic pairs, both models, stability, real-world.
- **Protocol:** frozen at tag `protocol-freeze`. Two post-review corrections changed only the extractor and are tagged `review-correction-1` (D-R1) and `review-correction-2` (D-R2). Neither changed a held-out evidence record, decision or score.
- **Reviews:** GPT Pro reviewed twice (`docs/review/gptpro-2026-10-23/`, `docs/review/gptpro-2026-10-25/`), and both responses are next to the reviews. The second review scored the project about 80/100 before its corrections were applied.
- **Replay:** the offline runs `corr-r2-test-*` (2026-10-25, Windows, Semgrep 1.182.1) reproduce every per-alert decision and score of the frozen runs with 0 uncached calls.
- **Report** (`report/`): 9 pages including references, ACM sigconf, no overfull boxes. Build in place with `latexmk -pdf main.tex`. On Windows, `-outdir=build` makes MiKTeX's bibtex hang.
- **Tests:** 99. On Windows 98 pass, and `test_diagnostic_label_evidence` fails because it assumes POSIX paths.

## Open items

1. Yufan edits the three `[confirm]` sentences in `report/sections/ai_usage.tex` so that they state what Yufan actually did.
2. Check the public repository link from a logged-out browser, then build the final PDF.
3. Deadline: 30 Nov 2026, 23:59 SGT. Submit the PDF with the repo link.

## Setting up on a new machine

1. Follow `README.md` § Setup: venv, `pip install -e . semgrep==1.182.1 pytest`, and the three pinned `git clone`s into `data/downloads/`.
2. Put the SoCLaaS key in `.env` (not in git). The API needs the NUS network or VPN.
3. **Response cache (optional, for `--offline` replay):** not published. Copies are in `results/llm_cache/` on the Mac and on the Windows machine (gitignored). Copy that folder across.
4. `python -m pytest -q tests`, then e.g. `python -m neurosym.cli run --correction --offline --subjects diag:test --name corr-replay-diag --model qwen3-coder-next` (any new `corr-` name).

## Rules

- Never print or commit `.env`.
- All LLM calls go through `neurosym.llm.LLM`, on SoCLaaS only. Do not use paid APIs or the Claude subscription for experiments.
- The frozen paths are listed in `src/neurosym/pipeline.py::FROZEN_PATHS`. Changing them invalidates test runs.
