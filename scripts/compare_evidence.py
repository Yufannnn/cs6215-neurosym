"""Re-extract every archived alert with the current extractor and compare against the frozen run.

Reports, per run, which evidence records changed, whether the E prompt changed (and so whether the archived
E response still answers the exact same input), and how D's decision changed. Reads only; writes nothing
unless --out is given.
"""
import argparse
import json
from pathlib import Path

from neurosym import evidence, refine, triage
from neurosym.config import RESULTS, local_path


def compare(run: str) -> dict:
    d = RESULTS / "runs" / run
    alerts = [json.loads(l) for l in (d / "baseline" / "alerts.jsonl").read_text().splitlines()]
    frozen_D = {r["alert_id"]: r for r in map(json.loads, (d / "decisions_D.jsonl").read_text().splitlines())}
    out = []
    for a in alerts:
        a = {**a, "path": str(local_path(a["path"]))}
        old_path = d / "evidence" / f"{a['alert_id']}.json"
        old = json.loads(old_path.read_text()) if old_path.exists() else None
        try:
            new = json.loads(json.dumps(evidence.extract(a["path"], a["line"], a["col"], a["end_line"], a["end_col"]),
                                        default=str))
        except evidence.Unsupported:
            new = None
        same_record = old == new
        same_prompt = same_record or (old is not None and new is not None and
                                      triage.build_messages("E", a, old) == triage.build_messages("E", a, new))
        new_D = refine.deterministic(new)["decision"] if new else "retain"
        row = {"alert_id": a["alert_id"], "unit": a["unit"], "same_record": same_record, "same_E_prompt": same_prompt,
               "D_frozen": frozen_D[a["alert_id"]]["decision"], "D_corrected": new_D}
        if not same_record:
            row["changed_facts"] = {k: [old["facts"].get(k) if old else None, new["facts"].get(k) if new else None]
                                    for k in (new or old)["facts"]
                                    if (old or {}).get("facts", {}).get(k) != (new or {}).get("facts", {}).get(k)}
        out.append(row)
    return {"run": run, "alerts": len(out), "records_changed": sum(not r["same_record"] for r in out),
            "E_prompts_changed": sum(not r["same_E_prompt"] for r in out),
            "D_changed": sum(r["D_frozen"] != r["D_corrected"] for r in out), "rows": out}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="*")
    ap.add_argument("--out")
    args = ap.parse_args()
    runs = args.runs or sorted(p.name for p in (RESULTS / "runs").iterdir() if (p / "decisions_D.jsonl").exists())
    res = [compare(r) for r in runs]
    for r in res:
        print(f"{r['run']:18s} alerts={r['alerts']:3d} records_changed={r['records_changed']:3d} "
              f"E_prompts_changed={r['E_prompts_changed']:3d} D_changed={r['D_changed']}")
        for row in r["rows"]:
            if not row["same_record"]:
                print("   ", row["unit"], row.get("changed_facts"), row["D_frozen"], "->", row["D_corrected"])
    if args.out:
        Path(args.out).write_text(json.dumps(res, indent=1))
