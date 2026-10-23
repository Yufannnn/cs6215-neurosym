| Run | Model | Triage jobs (alerts x L,E) | Completion requests (incl. schema repair) | Uncached | Prompt tokens | Completion tokens | LLM wall time (s) | Transport retries | Backend |
|---|---|---|---|---|---|---|---|---|---|
| test-owasp-qcn | qwen3-coder-next | 136 | 137 | 137 | 322,782 | 27,529 | 347 | 80 | vllm-0.26.0-1cf708c9 |
| test-owasp-q9b | qwen3.5:9b | 136 | 136 | 136 | 351,325 | 21,446 | 1529 | 11 | fp_ollama |
| test-diag-qcn | qwen3-coder-next | 84 | 87 | 87 | 104,463 | 27,143 | 235 | 43 | vllm-0.26.0-1cf708c9 |
| test-diag-q9b | qwen3.5:9b | 84 | 84 | 84 | 99,690 | 13,835 | 500 | 37 | fp_ollama |

Whole project to date (development + test + stability): 874 uncached requests, 2,003,573 tokens (caps: 1,500 requests, 12M tokens).
