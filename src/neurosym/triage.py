"""Arms L and E: prompt construction, model calls and JSON validation."""
import json
from importlib import resources

from . import evidence as ev
from .llm import LLM
from .refine import REASON_KINDS

PROMPT_VERSION = "p2"
MAX_INPUT_TOKENS = 12_000
MAX_OUTPUT_TOKENS = 2_000
DECISIONS = ("retain", "suppress", "unknown")
STATUSES = ("holds", "refuted", "unknown")
_REPAIR = "Your previous reply was not a valid JSON object with the required fields. Reply again with only the JSON object."


def _template(name: str) -> str:
    return resources.files("neurosym").joinpath(f"prompts/{name}.txt").read_text()


def estimate_tokens(text: str) -> int:
    return len(text) // 3 + 1  # conservative for code-heavy prompts


def evidence_view(record: dict) -> dict:
    """The part of the EvidenceRecord shown to the model (no file hashes, no labels, no case IDs)."""
    keep = ("sink", "nodes", "definitions", "branches", "path_conditions_at_sink", "transformations", "facts")
    return {k: record[k] for k in keep}


def summary(record: dict) -> str:
    """Plain-language digest of the facts, placed before the full JSON evidence."""
    f = record["facts"]
    lines = [f"- Value reaching the operation: {f['sink_value']} (kind: {f['sink_value_kind']}).",
             f"- Analysis complete for this function: {'yes' if f['complete'] else 'no: ' + '; '.join(f['incomplete_reasons'])}.",
             f"- Operation reachable: {'no' if f['sink_unreachable'] else 'yes'}."]
    infeasible = [f"{b['id']} ({b['condition']}): " + ("never true" if b["feasible_true"] is False else "never false")
                  for b in record["branches"] if b["feasible_true"] is False or b["feasible_false"] is False]
    lines.append("- Branches that can never take one side: " + ("; ".join(infeasible) if infeasible else "none") + ".")
    pruned = f["pruned_tainted_definitions"]
    lines.append("- Attacker-controlled definitions only on paths that cannot execute: " + (", ".join(pruned) or "none") + ".")
    conds = [f"{c['id']} `{c['condition']}` must be {c['polarity_to_reach_sink']} to reach the operation"
             f" (constrains the used value: {'yes' if c['guards_sink_value'] else 'no'};"
             f" covers every attacker flow: {'yes' if c['covers_all_tainted_flows'] else 'no'})"
             for c in record["path_conditions_at_sink"] if c["kind"] != "match_case"]
    lines.append("- Conditions dominating the operation: " + ("; ".join(conds) if conds else "none") + ".")
    sound = [f"{g['guard']} ({g['recognizer']})" for g in f["containment_guards"]]
    lines.append("- Checks recognised as sound directory containment: " + (", ".join(sound) or "none") + ".")
    return "\n".join(lines)


def build_messages(arm: str, alert: dict, record: dict | None) -> list[dict]:
    source = ev.function_source(alert["path"], alert["line"])
    sink = record["sink"] if record else {"api": "?", "argument": "?", "statement": "?"}
    fields = {"argument": sink["argument"], "api": sink["api"], "line": alert["line"], "source": source,
              "sink_statement": sink.get("statement", "?")}
    if arm == "E":
        fields["evidence"] = json.dumps(evidence_view(record), indent=1, default=str)
        fields["summary"] = summary(record)
    user = _template(arm).format(**fields)
    return [{"role": "system", "content": _template("system")}, {"role": "user", "content": user}]


def validate(arm: str, text: str) -> tuple[dict | None, str]:
    """Parse and schema-check a reply. Returns (verdict or None, status)."""
    try:
        obj = json.loads(text.strip().removeprefix("```json").removesuffix("```").strip())
    except (json.JSONDecodeError, AttributeError):
        return None, "not_json"
    if not isinstance(obj, dict) or obj.get("decision") not in DECISIONS:
        return None, "bad_decision"
    if obj.get("reason_kind") not in REASON_KINDS:
        return None, "bad_reason_kind"
    if arm == "E":
        obs = obj.get("obligations")
        if isinstance(obs, dict):  # tolerate the bare-string form {"control": "refuted"}
            obs = {k: ({"status": v, "node_ids": []} if isinstance(v, str) else v) for k, v in obs.items()}
            obj["obligations"] = obs
        if not isinstance(obs, dict) or any(not isinstance(obs.get(k), dict) or obs[k].get("status") not in STATUSES
                                            for k in ("control", "flow", "confinement", "coverage")):
            return None, "bad_obligations"
        if not isinstance(obj.get("evidence_node_ids", []), list):
            return None, "bad_node_ids"
    return obj, "ok"


def triage(arm: str, alert: dict, record: dict | None, llm: LLM, replicate: int = 0) -> dict:
    """One logical call (plus at most one schema-repair retry). Failures retain the warning."""
    if arm == "E" and record is None:
        return {"decision": "retain", "raw_decision": None, "verdict": None, "status": "no_evidence", "calls": []}
    messages = build_messages(arm, alert, record)
    if estimate_tokens("".join(m["content"] for m in messages)) > MAX_INPUT_TOKENS:
        return {"decision": "retain", "raw_decision": None, "verdict": None, "status": "over_input_budget", "calls": []}
    calls = []
    try:
        reply = llm.complete(messages, replicate=replicate, response_format={"type": "json_object"})
        calls.append(_meta(reply))
        verdict, status = validate(arm, reply.content)
        if verdict is None:
            retry = messages + [{"role": "assistant", "content": reply.content}, {"role": "user", "content": _REPAIR}]
            reply = llm.complete(retry, replicate=replicate, response_format={"type": "json_object"})
            calls.append(_meta(reply) | {"repair": True})
            verdict, status = validate(arm, reply.content)
            status = f"repaired_{status}" if verdict else f"invalid_{status}"
    except LookupError:
        raise
    except Exception as e:  # transport / service failure: keep the warning
        return {"decision": "retain", "raw_decision": None, "verdict": None, "status": f"error:{type(e).__name__}",
                "error": str(e)[:300], "calls": calls}
    decision = verdict["decision"] if verdict else "retain"
    return {"decision": "suppress" if decision == "suppress" else "retain", "raw_decision": decision,
            "verdict": verdict, "status": status, "calls": calls}


def _meta(reply) -> dict:
    return {"cache_key": reply.cache_key, "cached": reply.cached, "served_model": reply.served_model,
            "fingerprint": reply.fingerprint, "prompt_tokens": reply.prompt_tokens,
            "completion_tokens": reply.completion_tokens, "latency_s": reply.latency_s,
            "finish_reason": reply.finish_reason, "content": reply.content}
