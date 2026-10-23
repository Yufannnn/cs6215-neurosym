"""Fresh-generation stability: 3 new replicates (cache bypassed by replicate ID) on a seeded, stratified sample."""
import json
import random
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from . import refine, triage
from .config import RESULTS
from .llm import LLM
from .pipeline import load_models

SEED, SAMPLE, REPLICATES = 6215, 30, (1, 2, 3)


def _load(run):
    d = RESULTS / "runs" / run
    alerts = [json.loads(l) for l in (d / "baseline" / "alerts.jsonl").read_text().splitlines()]
    dec = {arm: {json.loads(l)["alert_id"]: json.loads(l) for l in (d / f"decisions_{arm}.jsonl").read_text().splitlines()}
           for arm in ("E", "L", "EC")}
    recs = {a["alert_id"]: json.loads((d / "evidence" / f"{a['alert_id']}.json").read_text())
            for a in alerts if (d / "evidence" / f"{a['alert_id']}.json").exists()}
    return alerts, dec, recs


def sample(runs):
    """Stratify by the frozen E decision (suppress / retain), 15 each where available, seeded."""
    pool = []
    for run in runs:
        alerts, dec, recs = _load(run)
        pool += [(run, a, recs.get(a["alert_id"]), dec) for a in alerts if a["alert_id"] in recs]
    rng = random.Random(SEED)
    strata = {s: [p for p in pool if p[3]["E"][p[1]["alert_id"]]["decision"] == s] for s in ("suppress", "retain")}
    out = []
    for s, items in strata.items():
        rng.shuffle(items)
        out += items[:SAMPLE // 2]
    return out


def run(runs=("test-owasp-qcn", "test-diag-qcn"), model="qwen3-coder-next", workers=2, offline=False, out=None):
    """Fresh replicates (or, offline, a replay of the stored ones). With out, also writes every raw reply."""
    cfg = load_models()[model]
    picked = sample(runs)
    results, raw = [], []
    for arm in ("L", "E"):
        llm = LLM(model=model, max_tokens=triage.MAX_OUTPUT_TOKENS, tag=f"stability:{arm}",
                  extra_body=cfg["extra_body"], version=f"{triage.PROMPT_VERSION}:{arm}", offline=offline)
        jobs = [(p, r) for p in picked for r in REPLICATES]
        with ThreadPoolExecutor(workers) as pool:
            outs = list(pool.map(lambda j: triage.triage(arm, j[0][1], j[0][2], llm, replicate=j[1]), jobs))
        for (p, r), o in zip(jobs, outs):
            run_name, alert, rec, dec = p
            row = {"run": run_name, "alert_id": alert["alert_id"], "unit": alert["unit"], "arm": arm, "replicate": r,
                   "decision": o["decision"], "frozen_decision": dec[arm][alert["alert_id"]]["decision"],
                   "status": o["status"], "fresh": all(not c["cached"] for c in o["calls"])}
            if arm == "E":
                g = refine.gate(rec, o.get("verdict"))
                row["ec_decision"] = "suppress" if g["suppress"] else "retain"
                row["ec_frozen_decision"] = dec["EC"][alert["alert_id"]]["decision"]
            results.append(row)
            raw.append({k: row[k] for k in ("run", "alert_id", "arm", "replicate", "status")}
                       | {"verdict": o.get("verdict"), "calls": [{k: c.get(k) for k in ("cache_key", "served_model",
                          "fingerprint", "prompt_tokens", "completion_tokens", "finish_reason", "content")} for c in o["calls"]]})
    if out:
        Path(out).write_text("".join(json.dumps(x) + "\n" for x in raw))
    if not offline:
        (RESULTS / "stability.json").write_text(json.dumps(results, indent=1))
    return results


def summarize(results):
    """Per arm: how often 3 fresh replicates agree with each other and with the frozen replicate 0."""
    out = {}
    for arm, src, key, frozen in (("L", "L", "decision", "frozen_decision"), ("E", "E", "decision", "frozen_decision"),
                                  ("EC", "E", "ec_decision", "ec_frozen_decision")):
        by_alert = {}
        for r in results:
            if r["arm"] == src:
                by_alert.setdefault(r["alert_id"], []).append(r)
        n = len(by_alert)
        unanimous = sum(len({x[key] for x in rs}) == 1 for rs in by_alert.values())
        agree_frozen = sum(all(x[key] == x[frozen] for x in rs) for rs in by_alert.values())
        decisions = [x[key] for rs in by_alert.values() for x in rs]
        out[arm] = {"alerts": n, "fresh_calls": sum(x["fresh"] for rs in by_alert.values() for x in rs) if arm != "EC" else None,
                    "replicates_unanimous": unanimous, "all_replicates_match_frozen": agree_frozen,
                    "decision_flip_rate": round(sum(x[key] != x[frozen] for rs in by_alert.values() for x in rs)
                                                / max(len(decisions), 1), 4)}
    return out
