"""Run the S/D/L/E/EC comparison on one subject set and write a self-describing run directory."""
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path

from . import baseline, evidence, refine, scoring, triage
from .config import RESULTS, ROOT
from .llm import LLM

ARMS = ("S", "D", "L", "E", "EC")
# The method and protocol: changing any of these after protocol-freeze invalidates test-split runs.
FROZEN_PATHS = ["baseline/rules", "configs", "data/owasp_split.csv", "data/diagnostics/manifest.csv",
                "data/diagnostics/dev", "data/diagnostics/test", "docs/protocol.md",
                "src/neurosym/evidence.py", "src/neurosym/refine.py", "src/neurosym/triage.py",
                "src/neurosym/prompts", "src/neurosym/baseline.py", "src/neurosym/scoring.py",
                "src/neurosym/pipeline.py", "src/neurosym/llm.py", "src/neurosym/owasp.py"]


@dataclass(frozen=True)
class Subject:
    unit: str
    path: Path
    gold: bool | None
    family: str
    split: str
    corpus: str


def git_state() -> dict:
    def git(*args):
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    return {"commit": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain", "--", *FROZEN_PATHS)),
            "freeze_tag": git("rev-parse", "-q", "--verify", "refs/tags/protocol-freeze") or None}


def require_frozen() -> None:
    """Test data may only be evaluated by the frozen protocol, policy, prompts and code."""
    g = git_state()
    if not g["freeze_tag"]:
        raise SystemExit("refusing to evaluate test data: tag protocol-freeze does not exist")
    changed = subprocess.run(["git", "diff", "--name-only", "protocol-freeze", "--", *FROZEN_PATHS],
                             cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if changed or g["dirty"]:
        raise SystemExit(f"refusing to evaluate test data: frozen files changed since protocol-freeze:\n{changed}")


def load_models() -> dict:
    return json.loads((ROOT / "configs" / "models.json").read_text())


def run(name: str, subjects: list[Subject], arms=ARMS, model: str = "qwen3-coder-next", replicate: int = 0,
        offline: bool = False, workers: int = 3, llm_factory=None) -> dict:
    out = RESULTS / "runs" / name
    (out / "evidence").mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()
    alerts = [asdict(a) for a in baseline.run({s.unit: s.path for s in subjects}, out / "baseline")]
    t_baseline = time.monotonic() - t0

    records, extraction = {}, {}
    t0 = time.monotonic()
    for a in alerts:
        try:
            records[a["alert_id"]] = evidence.extract(a["path"], a["line"], a["col"], a["end_line"], a["end_col"])
            extraction[a["alert_id"]] = "ok"
            (out / "evidence" / f"{a['alert_id']}.json").write_text(json.dumps(records[a["alert_id"]], indent=1, default=str))
        except evidence.Unsupported as e:
            records[a["alert_id"]], extraction[a["alert_id"]] = None, f"unsupported: {e}"
    t_extract = time.monotonic() - t0

    decisions = {arm: {} for arm in arms}
    for a in alerts:
        aid, rec = a["alert_id"], records[a["alert_id"]]
        if "S" in arms:
            decisions["S"][aid] = {"decision": "retain"}
        if "D" in arms:
            decisions["D"][aid] = refine.deterministic(rec) if rec else {"decision": "retain", "recognizer": None,
                                                                         "note": extraction[aid]}
    cfg = load_models()[model]
    llm_time = {}
    for arm in [x for x in ("L", "E") if x in arms or (x == "E" and "EC" in arms)]:
        llm = (llm_factory or LLM)(model=model, max_tokens=triage.MAX_OUTPUT_TOKENS, tag=f"{name}:{arm}",
                                   extra_body=cfg["extra_body"], version=f"{triage.PROMPT_VERSION}:{arm}",
                                   offline=offline)
        t0 = time.monotonic()
        with ThreadPoolExecutor(workers) as pool:
            res = list(pool.map(lambda a: triage.triage(arm, a, records[a["alert_id"]], llm, replicate), alerts))
        llm_time[arm] = time.monotonic() - t0
        decisions.setdefault(arm, {})
        for a, r in zip(alerts, res):
            decisions[arm][a["alert_id"]] = r
    if "EC" in arms:
        for a in alerts:
            e = decisions["E"][a["alert_id"]]
            g = refine.gate(records[a["alert_id"]], e.get("verdict"), a["file_sha256"]) if records[a["alert_id"]] else \
                {"suppress": False, "check": "fail", "category": None, "reason": "no evidence"}
            decisions["EC"][a["alert_id"]] = {"decision": "suppress" if g["suppress"] else "retain", "gate": g,
                                              "e_decision": e["decision"], "e_cache_keys": [c["cache_key"] for c in e["calls"]]}
    if "E" in decisions and "E" not in arms:
        del decisions["E"]

    for arm, per in decisions.items():
        (out / f"decisions_{arm}.jsonl").write_text(
            "".join(json.dumps({"alert_id": k, **v}, default=str) + "\n" for k, v in per.items()))
    units = [{"unit": s.unit, "gold": s.gold, "family": s.family} for s in subjects if s.gold is not None]
    scores = scoring.score(units, alerts, decisions) if units else {}
    (out / "scores.json").write_text(json.dumps(scores, indent=1))
    calls = [c for arm in ("L", "E") if arm in decisions for d in decisions[arm].values() for c in d.get("calls", [])]
    manifest = {
        "name": name, "arms": list(decisions), "model": model, "model_config": cfg, "replicate": replicate,
        "prompt_version": triage.PROMPT_VERSION, "offline_replay": offline, "git": git_state(),
        "baseline": baseline.environment(), "subjects": len(subjects),
        "corpora": sorted({s.corpus for s in subjects}), "splits": sorted({s.split for s in subjects}),
        "alerts": len(alerts), "extraction": {k: sum(v == k for v in extraction.values()) for k in ("ok",)}
        | {"unsupported": sum(v != "ok" for v in extraction.values())},
        "timing_s": {"baseline": round(t_baseline, 2), "extraction": round(t_extract, 2),
                     **{f"llm_{k}": round(v, 2) for k, v in llm_time.items()}},
        "llm": {"calls": len(calls), "uncached_calls": sum(not c["cached"] for c in calls),
                "prompt_tokens": sum(c["prompt_tokens"] or 0 for c in calls),
                "completion_tokens": sum(c["completion_tokens"] or 0 for c in calls),
                "served_models": sorted({c["served_model"] for c in calls if c["served_model"]}),
                "fingerprints": sorted({c["fingerprint"] for c in calls if c["fingerprint"]})},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1))
    return {"manifest": manifest, "scores": scores, "out": out}
