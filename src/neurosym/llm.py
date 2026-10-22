"""SoCLaaS chat client.

Every request is cached on disk (keyed by the exact request) so reruns are reproducible
and free, and every call is appended to results/llm_calls.jsonl with the model that
actually served it, token usage and latency, for the report's resource-budget section.
"""
import hashlib
import json
import time
from datetime import datetime, timezone

from openai import OpenAI

from .config import RESULTS, load_env

CACHE_DIR = RESULTS / "llm_cache"
LOG_PATH = RESULTS / "llm_calls.jsonl"


class LLM:
    def __init__(self, model: str | None = None, temperature: float = 0.0,
                 max_tokens: int = 4096, cache: bool = True, tag: str = "untagged"):
        env = load_env()
        self.client = OpenAI(base_url=env["SOCLAAS_BASE_URL"], api_key=env["SOCLAAS_API_KEY"])
        self.model = model or env.get("SOCLAAS_MODEL", "default")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.cache = cache
        self.tag = tag  # which pipeline stage / experiment made the call

    def chat(self, messages: list[dict], **extra) -> str:
        request = {"model": self.model, "messages": messages, "temperature": self.temperature,
                   "max_tokens": self.max_tokens, **extra}
        key = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
        path = CACHE_DIR / f"{key}.json"

        if self.cache and path.exists():
            response, cached = json.loads(path.read_text()), True
        else:
            start = time.monotonic()
            response = self.client.chat.completions.create(**request).model_dump()
            response["_latency_s"] = round(time.monotonic() - start, 3)
            cached = False
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"request": request, **response}))

        usage = response.get("usage") or {}
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a") as log:
            log.write(json.dumps({
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "tag": self.tag, "cache_key": key, "cached": cached,
                "requested_model": self.model, "served_model": response.get("model"),
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
                "latency_s": response.get("_latency_s"),
            }) + "\n")
        return response["choices"][0]["message"]["content"]
