"""Cache replay vs fresh replicates; offline mode never touches the network."""
import json

import pytest

from neurosym import llm as llm_mod


class _Resp:
    def __init__(self, n):
        self.n = n

    def model_dump(self):
        return {"model": "m", "system_fingerprint": "fp", "usage": {"prompt_tokens": 3, "completion_tokens": 1},
                "choices": [{"message": {"content": f"answer{self.n}"}, "finish_reason": "stop"}]}


class _Client:
    def __init__(self):
        self.n = 0
        self.chat = self
        self.completions = self

    def create(self, **request):
        self.n += 1
        return _Resp(self.n)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(llm_mod, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(llm_mod, "LOG_PATH", tmp_path / "log.jsonl")
    c = llm_mod.LLM(model="m", offline=True)
    c.offline, c.client = False, _Client()
    return c


def test_replay_is_not_a_fresh_call(client):
    msgs = [{"role": "user", "content": "x"}]
    first, second = client.complete(msgs), client.complete(msgs)
    assert not first.cached and second.cached and first.content == second.content and client.client.n == 1


def test_new_replicate_is_a_fresh_call_and_keeps_frozen_set(client):
    msgs = [{"role": "user", "content": "x"}]
    base = client.complete(msgs, replicate=0)
    fresh = client.complete(msgs, replicate=1)
    again = client.complete(msgs, replicate=0)
    assert not fresh.cached and fresh.cache_key != base.cache_key and again.content == base.content


def test_offline_miss_raises(client):
    client.offline = True
    with pytest.raises(LookupError):
        client.complete([{"role": "user", "content": "never seen"}])


def test_log_records_served_model_and_fingerprint(client):
    client.complete([{"role": "user", "content": "y"}])
    row = json.loads(llm_mod.LOG_PATH.read_text().splitlines()[-1])
    assert row["served_model"] == "m" and row["fingerprint"] == "fp" and row["cached"] is False
