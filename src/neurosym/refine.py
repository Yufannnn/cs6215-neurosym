"""Arm D (closed-set deterministic recognizers) and the EC evidence gate. Both read the same extracted facts."""

REASON_KINDS = ("constant_or_overwritten_value", "unreachable_reported_flow", "guarded_path_confinement",
                "trusted_base_safe_api", "unresolved")


def deterministic(record: dict) -> dict:
    """Arm D: suppress only when a recognizer proves the warning cannot carry attacker data to the sink."""
    f = record["facts"]
    if f["complete"]:
        if f["sink_unreachable"]:
            return {"decision": "suppress", "recognizer": "unreachable_sink"}
        if f["sink_value_kind"] in ("constant", "trusted"):
            kind = "unreachable_reported_flow" if f["pruned_tainted_definitions"] else "constant_or_overwritten_value"
            return {"decision": "suppress", "recognizer": kind}
        if f["safe_api"]:
            return {"decision": "suppress", "recognizer": "trusted_base_safe_api"}
        if f["containment_guards"]:
            return {"decision": "suppress", "recognizer": "sound_containment"}
    return {"decision": "retain", "recognizer": None}


def gate(record: dict, verdict: dict | None, file_sha256: str | None = None) -> dict:
    """EC: accept an E suppression only if its claimed evidence is consistent with the extracted facts.

    Returns {"suppress": bool, "check": pass|fail|not_applicable, "category": ..., "reason": ...}.
    category is structural_check_passed, trusted_contract_matched or semantic_judgment_remaining.
    """
    if verdict is None:
        return _keep("fail", "invalid or missing model output")
    if file_sha256 is not None and record.get("file_sha256") != file_sha256:
        return _keep("fail", "evidence was computed for a different file version")
    if verdict.get("decision") != "suppress":
        return _keep("not_applicable", f"model decision {verdict.get('decision')}")
    f = record["facts"]
    known = {n["id"] for n in record["nodes"]} | {d["id"] for d in record["definitions"]} | {"params"}
    cited = set(verdict.get("evidence_node_ids") or [])
    for ob in (verdict.get("obligations") or {}).values():
        cited |= set((ob or {}).get("node_ids") or [])
    if not cited:
        return _keep("fail", "no evidence nodes cited")
    if cited - known:
        return _keep("fail", f"cited nodes do not exist: {sorted(cited - known)}")
    if not f["complete"]:
        return _keep("fail", "evidence incomplete for any suppression claim: " + "; ".join(f["incomplete_reasons"]))
    kind = verdict.get("reason_kind")
    if kind in ("constant_or_overwritten_value", "unreachable_reported_flow"):
        if f["sink_unreachable"] or f["sink_value_kind"] in ("constant", "trusted"):
            return _drop("structural_check_passed", "sink value is untainted on every feasible path")
        return _keep("fail", f"sink value is {f['sink_value_kind']}; constant/unreachable claim not supported")
    if kind == "trusted_base_safe_api":
        if f["safe_api"]:
            return _drop("trusted_contract_matched", "documented safe API with preconditions met")
        return _keep("fail", "no documented safe API applies")
    if kind == "guarded_path_confinement":
        conf = (verdict.get("obligations") or {}).get("confinement") or {}
        if conf.get("status") != "holds":
            return _keep("fail", "confinement obligation not asserted")
        guards = {c["id"]: c for c in record["path_conditions_at_sink"]}
        cited_guards = [g for g in conf.get("node_ids") or [] if g in guards]
        if not cited_guards:
            return _keep("fail", "confinement does not cite a condition that dominates the sink")
        good = [g for g in cited_guards if guards[g]["covers_all_tainted_flows"]]
        if not good:
            return _keep("fail", "cited guard does not constrain the value consumed at the sink on every tainted flow")
        sound = {c["guard"] for c in f["containment_guards"]}
        if any(g in sound for g in good):
            return _drop("trusted_contract_matched", "guard matches a sound containment recognizer")
        return _drop("semantic_judgment_remaining", "guard is structurally valid; its sufficiency is the model's judgment")
    return _keep("fail", f"reason kind {kind!r} cannot justify suppression")


def _keep(check, reason):
    return {"suppress": False, "check": check, "category": None, "reason": reason}


def _drop(category, reason):
    return {"suppress": True, "check": "pass", "category": category, "reason": reason}
