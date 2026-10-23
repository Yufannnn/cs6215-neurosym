"""EC gate, model-output validation, scoring identities and leakage controls."""
import json

import pytest

from neurosym import owasp, refine, scoring, triage
from neurosym.llm import Reply

from helpers import record_for

GUARDED = """
def handler():
    bar = request.headers.get("f")
    if '../' in bar:
        return "no"
    fileName = f'{ROOT}/{bar}'
    return open(fileName, 'wb')
"""
CONSTANT = """
def handler():
    name = request.args.get("f")
    name = "fixed.txt"
    return open(os.path.join(ROOT, name)).read()
"""


def verdict(kind, nodes, confinement=("unknown", [])):
    return {"decision": "suppress", "reason_kind": kind, "evidence_node_ids": nodes,
            "obligations": {"control": {"status": "refuted", "node_ids": []}, "flow": {"status": "refuted", "node_ids": []},
                            "confinement": {"status": confinement[0], "node_ids": confinement[1]},
                            "coverage": {"status": "holds", "node_ids": []}}}


def test_gate_accepts_matching_constant_claim(tmp_path):
    r = record_for(tmp_path, CONSTANT)
    g = refine.gate(r, verdict("constant_or_overwritten_value", [r["definitions"][-1]["id"]]), r["file_sha256"])
    assert g["suppress"] and g["category"] == "structural_check_passed"


def test_gate_rejects_wrong_node_ids(tmp_path):
    r = record_for(tmp_path, CONSTANT)
    assert not refine.gate(r, verdict("constant_or_overwritten_value", ["s99"]))["suppress"]


def test_gate_rejects_stale_file_hash(tmp_path):
    r = record_for(tmp_path, CONSTANT)
    g = refine.gate(r, verdict("constant_or_overwritten_value", [r["nodes"][0]["id"]]), "0" * 64)
    assert not g["suppress"] and "different file" in g["reason"]


def test_gate_rejects_constant_claim_on_tainted_value(tmp_path):
    r = record_for(tmp_path, GUARDED)
    assert not refine.gate(r, verdict("constant_or_overwritten_value", [r["nodes"][0]["id"]]))["suppress"]


def test_gate_guard_claim_is_semantic_judgment(tmp_path):
    r = record_for(tmp_path, GUARDED)
    guard = r["path_conditions_at_sink"][0]["id"]
    g = refine.gate(r, verdict("guarded_path_confinement", [guard], ("holds", [guard])))
    assert g["suppress"] and g["category"] == "semantic_judgment_remaining"


def test_gate_guard_claim_must_cite_dominating_guard(tmp_path):
    r = record_for(tmp_path, GUARDED)
    other = r["nodes"][0]["id"]
    assert not refine.gate(r, verdict("guarded_path_confinement", [other], ("holds", [other])))["suppress"]


def test_gate_guard_on_other_value_rejected(tmp_path):
    r = record_for(tmp_path, """
def handler():
    other = request.args.get("g")
    if '..' in other:
        return "no"
    return open(os.path.join(ROOT, request.args.get("f"))).read()
""")
    guard = r["path_conditions_at_sink"][0]["id"]
    assert not refine.gate(r, verdict("guarded_path_confinement", [guard], ("holds", [guard])))["suppress"]


def test_gate_incomplete_evidence_retains(tmp_path):
    r = record_for(tmp_path, """
def handler():
    parts = []
    alias = parts
    alias.append(request.args.get("f"))
    parts.append('x')
    return open(os.path.join(ROOT, parts[0])).read()
""")
    assert not refine.gate(r, verdict("constant_or_overwritten_value", [r["nodes"][0]["id"]]))["suppress"]


def test_gate_missing_or_unresolved_retains(tmp_path):
    r = record_for(tmp_path, CONSTANT)
    assert not refine.gate(r, None)["suppress"]
    v = verdict("unresolved", [r["nodes"][0]["id"]])
    assert not refine.gate(r, v)["suppress"]
    v["decision"] = "retain"
    assert refine.gate(r, v)["check"] == "not_applicable"


def test_validate_rejects_malformed():
    assert triage.validate("L", "not json")[0] is None
    assert triage.validate("L", json.dumps({"decision": "maybe", "reason_kind": "unresolved"}))[0] is None
    assert triage.validate("L", json.dumps({"decision": "retain", "reason_kind": "bogus"}))[0] is None
    assert triage.validate("E", json.dumps({"decision": "retain", "reason_kind": "unresolved"}))[0] is None
    ok = {"decision": "retain", "reason_kind": "unresolved", "evidence_node_ids": [],
          "obligations": {k: "unknown" for k in ("control", "flow", "confinement", "coverage")}}
    assert triage.validate("E", json.dumps(ok))[1] == "ok"


class FakeLLM:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def complete(self, messages, replicate=0, **extra):
        self.calls.append(messages)
        content = self.replies.pop(0)
        if isinstance(content, Exception):
            raise content
        return Reply(content, False, "fake", None, 10, 5, 0.0, "stop", f"k{len(self.calls)}")


def _alert(tmp_path, body):
    record = record_for(tmp_path, body)
    import ast
    src = (tmp_path / "case.py").read_text()
    line = record["sink"]["line"]
    return {"path": str(tmp_path / "case.py"), "line": line}, record


def test_triage_repairs_once_then_retains(tmp_path):
    alert, rec = _alert(tmp_path, CONSTANT)
    out = triage.triage("L", alert, rec, FakeLLM(["nope", "still nope"]))
    assert out["decision"] == "retain" and out["status"].startswith("invalid") and len(out["calls"]) == 2


def test_triage_transport_error_retains(tmp_path):
    alert, rec = _alert(tmp_path, CONSTANT)
    out = triage.triage("E", alert, rec, FakeLLM([RuntimeError("down")]))
    assert out["decision"] == "retain" and out["status"] == "error:RuntimeError"


def test_prompts_never_contain_labels_or_case_ids():
    case = next(c for c in owasp.load("dev") if c.name == "BenchmarkTest00008")
    from neurosym import baseline, evidence
    src = case.path.read_text()
    import ast
    node = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call) and ast.unparse(n.func) == "p.exists")
    arg = node.func.value
    rec = evidence.extract(case.path, arg.lineno, arg.col_offset + 1, arg.end_lineno, arg.end_col_offset + 1)
    for arm in ("L", "E"):
        text = "".join(m["content"] for m in triage.build_messages(arm, {"path": str(case.path), "line": arg.lineno}, rec))
        assert "BenchmarkTest" not in text and "expectedresults" not in text and "pathtraver" not in text


def test_owasp_split_is_frozen_and_family_disjoint():
    dev, test = owasp.load("dev"), owasp.load("test")
    assert len(dev) + len(test) == 168
    assert not {c.family for c in dev} & {c.family for c in test}
    assert any(c.name == "BenchmarkTest00008" for c in dev)
    assert {(c.name, c.split) for c in owasp.compute_split()} == {(c.name, c.split) for c in dev + test}


def test_diagnostic_families_disjoint_and_labels_validated():
    from neurosym import diagnostics
    rows = diagnostics.manifest()
    fam = {s: {r["family"] for r in rows if r["split"] == s} for s in ("dev", "test")}
    assert not fam["dev"] & fam["test"]
    assert sum(r["split"] == "dev" for r in rows) == 24 and sum(r["split"] == "test" for r in rows) == 48


def test_diagnostic_label_evidence():
    """Vulnerable fixtures have an execution witness; safe ones completed runs without one and have a static
    justification (absence of a witness alone is not a proof)."""
    import csv
    from neurosym import diagnostics
    rows = {r["unit"]: r for r in diagnostics.validate_all()}
    just = {r["unit"] for r in csv.DictReader((diagnostics.DIAG / "safe_justification.csv").open())}
    for unit, r in rows.items():
        assert r["outcome"] == ("witness" if r["intended"] else "no_witness"), r
    assert just == {u for u, r in rows.items() if not r["intended"]}
    stored = {r["unit"]: r["outcome"] for r in csv.DictReader((diagnostics.DIAG / "label_validation.csv").open())}
    assert stored == {u: r["outcome"] for u, r in rows.items()}


def _units():
    return [{"unit": "a", "gold": True, "family": "f1"}, {"unit": "b", "gold": True, "family": "f2"},
            {"unit": "c", "gold": False, "family": "f3"}, {"unit": "d", "gold": False, "family": "f4"}]


def test_scoring_identities_and_na():
    units = _units()
    m = scoring.metrics(units, reported={"a", "c", "d"}, retained={"a", "d"})
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 1, 1, 1)
    assert m["tp_retention"] == 1.0 and m["fp_removal"] == 0.5
    assert abs(m["recall"] - m["baseline_recall"] * m["tp_retention"]) < 1e-12
    empty = scoring.metrics(units, reported=set(), retained=set())
    assert empty["precision"] is None and empty["tp_retention"] is None and empty["fp_removal"] is None


def test_duplicate_alerts_do_not_inflate_units():
    units = _units()
    alerts = [{"alert_id": "x1", "unit": "a"}, {"alert_id": "x2", "unit": "a"}, {"alert_id": "x3", "unit": "c"}]
    dec = {"S": {k: {"decision": "retain"} for k in ("x1", "x2", "x3")},
           "D": {"x1": {"decision": "suppress"}, "x2": {"decision": "retain"}, "x3": {"decision": "suppress"}}}
    s = scoring.score(units, alerts, dec)["metrics"]
    assert s["S"]["tp"] == 1 and s["D"]["tp"] == 1 and s["D"]["fp"] == 0


def test_retained_is_always_subset_of_baseline():
    import random
    rng = random.Random(0)
    units = _units()
    for _ in range(200):
        alerts = [{"alert_id": f"x{i}", "unit": rng.choice("abcd")} for i in range(rng.randint(0, 6))]
        dec = {"S": {a["alert_id"]: {"decision": "retain"} for a in alerts},
               "X": {a["alert_id"]: {"decision": rng.choice(["retain", "suppress"])} for a in alerts}}
        out = scoring.score(units, alerts, dec)
        assert set(out["retained_units"]["X"]) <= set(out["retained_units"]["S"])
        assert out["metrics"]["X"]["tp"] <= out["metrics"]["S"]["tp"]
