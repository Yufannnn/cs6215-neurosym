"""SoCLaaS chat client.

Every request is cached on disk, keyed by the exact request plus a replicate ID and the caller's
version tag, so reruns replay stored answers. A fresh replicate (new ID) never overwrites the frozen
response set. Every call is appended to results/llm_calls.jsonl with the served model, backend
fingerprint, token usage, cold latency and cache status, for the report's resource-budget section.
"""
import hashlib
import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import openai
from openai import OpenAI

from .config import RESULTS, load_env

CACHE_DIR = RESULTS / "llm_cache"
LOG_PATH = RESULTS / "llm_calls.jsonl"
_LOCK = threading.Lock()


@dataclass
class Reply:
    content: str
    cached: bool
    served_model: str | None
    fingerprint: str | None
    prompt_tokens: int | None
    completion_tokens: int | None
    latency_s: float | None
    finish_reason: str | None
    cache_key: str


class LLM:
    def __init__(self, model: str | None = None, temperature: float = 0.0, max_tokens: int = 4096,
                 cache: bool = True, tag: str = "untagged", extra_body: dict | None = None,
                 version: str = "", offline: bool = False):
        env = load_env() if not offline else {}
        self.client = None if offline else OpenAI(base_url=env["SOCLAAS_BASE_URL"], api_key=env["SOCLAAS_API_KEY"],
                                                  max_retries=0, timeout=180)
        self.model = model or env.get("SOCLAAS_MODEL", "default")
        self.temperature, self.max_tokens = temperature, max_tokens
        self.cache, self.tag, self.version = cache, tag, version
        self.extra_body = extra_body or {}
        self.offline = offline  # replay-only: a cache miss is an error, never a network call

    def complete(self, messages: list[dict], replicate: int = 0, **extra) -> Reply:
        request = {"model": self.model, "messages": messages, "temperature": self.temperature,
                   "max_tokens": self.max_tokens, **extra}
        if self.extra_body:
            request["extra_body"] = self.extra_body
        key_material = {"request": request, "replicate": replicate, "version": self.version}
        key = hashlib.sha256(json.dumps(key_material, sort_keys=True).encode()).hexdigest()
        path = CACHE_DIR / f"{key}.json"

        retries = 0
        if self.cache and path.exists():
            response, cached = json.loads(path.read_text()), True
        elif self.offline:
            raise LookupError(f"offline replay: no cached response for {key[:12]}")
        else:
            response, retries = self._call_with_backoff(request)
            cached = False
            with _LOCK:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({"request": request, "replicate": replicate,
                                            "version": self.version, **response}))

        usage = response.get("usage") or {}
        choice = response["choices"][0]
        reply = Reply(content=choice["message"].get("content") or "", cached=cached,
                      served_model=response.get("model"), fingerprint=response.get("system_fingerprint"),
                      prompt_tokens=usage.get("prompt_tokens"), completion_tokens=usage.get("completion_tokens"),
                      latency_s=response.get("_latency_s"), finish_reason=choice.get("finish_reason"), cache_key=key)
        with _LOCK:
            LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with LOG_PATH.open("a") as log:
                log.write(json.dumps({
                    "time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "tag": self.tag,
                    "version": self.version, "replicate": replicate, "cache_key": key, "cached": cached,
                    "requested_model": self.model, "served_model": reply.served_model,
                    "fingerprint": reply.fingerprint, "prompt_tokens": reply.prompt_tokens,
                    "completion_tokens": reply.completion_tokens, "latency_s": reply.latency_s,
                    "finish_reason": reply.finish_reason, "transport_retries": 0 if cached else retries,
                }) + "\n")
        return reply

    RETRYABLE = (openai.RateLimitError, openai.APIConnectionError, openai.APITimeoutError, openai.InternalServerError)

    def _call_with_backoff(self, request, attempts=7):
        """Transport-level retries only (rate limits, timeouts, 5xx); the answer itself is never retried."""
        for k in range(attempts):
            start = time.monotonic()
            try:
                response = self.client.chat.completions.create(**request).model_dump()
                response["_latency_s"] = round(time.monotonic() - start, 3)
                return response, k
            except self.RETRYABLE as e:
                if k == attempts - 1:
                    raise
                wait = None
                resp = getattr(e, "response", None)
                if resp is not None and resp.headers.get("retry-after"):
                    try:
                        wait = float(resp.headers["retry-after"])
                    except ValueError:
                        wait = None
                time.sleep(min(wait or 3 * 2 ** k, 90))

    def chat(self, messages: list[dict], **extra) -> str:
        return self.complete(messages, **extra).content
