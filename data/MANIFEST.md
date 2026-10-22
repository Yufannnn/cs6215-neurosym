# Data manifest

| Corpus | Origin | Exact revision | Licence | Labels | Split / exposure | Files |
|---|---|---|---|---|---|---|
| OWASP Benchmark for Python, `pathtraver` | https://github.com/OWASP-Benchmark/BenchmarkPython | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (2026-05-19) | GPL-3.0; fetched, not redistributed | Official `expectedresults-0.1.csv` (168 cases: 65 vulnerable, 103 safe). Reviewed cases in `adjudications.csv`; all scores use official labels | `owasp_split.csv`: seeded (6215) family split, dev 34 cases / 7 families, test 134 / 61. Design-exposed: `BenchmarkTest00008` (dev). Test opened only after tag `protocol-freeze` | `owasp_split.csv`, `adjudications.csv` |
| Diagnostic pairs | Written for this project from Python `os.path`/`pathlib`, Flask `send_from_directory` and OWASP Path Traversal guidance (reference per program in `diagnostics/manifest.csv`) | This repository | Same as repository | Intended labels, all 72 confirmed by execution against stubbed filesystem calls (`diagnostics/label_validation.csv`) | dev 12 pairs / 12 families; held-out 24 pairs / 12 families; families disjoint | `diagnostics/{build.py, manifest.csv, dev/, test/}` |
| PyVul CWE-22 fixes | https://github.com/billquan/PyVul | `1172bfd1579b4ad2a524549412170d08ca618fb3` | Upstream project licences | Target-level only: functions named by PyVul for the fix (fallback: functions touched by the diff); vulnerable at the parent revision, negative only for that defect at the fix revision | Deterministic feasibility screening of 51 commits (`realworld/screening.csv`); 6 pairs / 4 projects selected (`realworld/selected.json`) | `realworld/`, snapshots of changed files only |
| Semgrep community rules (reference only) | https://github.com/semgrep/semgrep-rules | `16b9e6d45f10649f6a531ec4838ed9924372c3bc` | Semgrep Rules License v1.0; fetched, not redistributed | n/a | Inspected; not used in the frozen rule | fetched into `downloads/` |

## Assumptions and exclusions

- POSIX path semantics; no symlink, race or Windows threats.
- The attacker controls Flask request data only.
- Real-world projects that do not use Flask's request API in the changed files were excluded, because they are outside the policy's threat model. Every exclusion is listed in `realworld/screening.csv` with its reason.
- Model inputs never include labels, expected-result files, test IDs, category routes, advisory text or commit messages.
