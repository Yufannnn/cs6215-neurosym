"""POST-HOC extension EC+ (designed after inspecting test-split failures; not part of the frozen protocol).

EC+ replays the frozen E responses (no new model calls) through the frozen EC gate plus two extra checks
for claims that EC would accept as `semantic_judgment_remaining`:
  1. containment-shaped but unsound: the guard uses startswith/commonpath/is_relative_to but does not
     match a sound containment recognizer -> do not defer to the model;
  2. attacker-influenced guard: the guard condition reads request data directly or a tainted definition
     outside the sink's slice, so the attacker may be able to switch the check off.
Results are reported separately as exploratory and must not be read as a held-out evaluation.
"""
import json
import re

from . import refine, scoring
from .config import RESULTS

CONTAINMENT_SHAPE = re.compile(r"\.startswith\(|commonpath\(|is_relative_to\(")
DIRECT_SOURCE = re.compile(r"\brequest\.|get_form_parameter|get_query_parameter|get_cookie")


def gate_plus(record, verdict, file_sha256=None) -> dict:
    g = refine.gate(record, verdict, file_sha256)
    if not g["suppress"] or g["category"] != "semantic_judgment_remaining":
        return g
    guards = {c["id"]: c for c in record["path_conditions_at_sink"]}
    cited = [guards[x] for x in (verdict["obligations"]["confinement"].get("node_ids") or []) if x in guards]
    defs = {d["id"]: d for d in record["definitions"]}
    for c in cited:
        if CONTAINMENT_SHAPE.search(c["condition"]):
            return {**g, "suppress": False, "check": "fail", "category": None,
                    "reason": "EC+: containment-shaped guard that is not a sound containment check"}
        outside = [d for ds in c["reads"].values() for d in ds if d in defs and defs[d]["tainted"] and not defs[d]["in_sink_slice"]]
        if DIRECT_SOURCE.search(c["condition"]) or outside:
            return {**g, "suppress": False, "check": "fail", "category": None,
                    "reason": "EC+: guard condition depends on other attacker-controlled input"}
    return g


def replay(run: str) -> dict:
    """Score EC+ on a saved run by replaying its E responses; returns metrics next to the frozen EC."""
    d = RESULTS / "runs" / run
    alerts = [json.loads(l) for l in (d / "baseline" / "alerts.jsonl").read_text().splitlines()]
    E = {json.loads(l)["alert_id"]: json.loads(l) for l in (d / "decisions_E.jsonl").read_text().splitlines()}
    dec = {"S": {a["alert_id"]: {"decision": "retain"} for a in alerts}, "EC": {}, "EC+": {}}
    for a in alerts:
        ev = d / "evidence" / f"{a['alert_id']}.json"
        rec = json.loads(ev.read_text()) if ev.exists() else None
        verdict = E[a["alert_id"]].get("verdict")
        for arm, fn in (("EC", refine.gate), ("EC+", gate_plus)):
            g = fn(rec, verdict, a["file_sha256"]) if rec else {"suppress": False}
            dec[arm][a["alert_id"]] = {"decision": "suppress" if g["suppress"] else "retain"}
    from .cli import load_subjects
    split = "dev" if run.startswith("dev") else "test"
    corpus = ("owasp:" if "owasp" in run else "diag:") + split
    units = [{"unit": s.unit, "gold": s.gold, "family": s.family} for s in load_subjects(corpus, allow_unfrozen=True)]
    return scoring.score(units, alerts, dec)["metrics"]
