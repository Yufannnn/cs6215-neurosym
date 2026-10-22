"""Check that SoCLaaS is reachable and the logging client works: python scripts/smoke_llm.py"""
import json

from neurosym.llm import LLM, LOG_PATH

reply = LLM(tag="smoke", cache=False).chat(
    [{"role": "user", "content": "Reply with exactly: OK"}], max_tokens=200)
print("reply:", reply.strip())
print("logged:", json.loads(LOG_PATH.read_text().splitlines()[-1]))
