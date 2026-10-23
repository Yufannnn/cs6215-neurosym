"""Real-world case study: manual defect mapping of the warnings in rw-vulnerable / rw-fixed.

Targets come from PyVul CWE-22 fix commits (data/realworld/selected.json). Each target is adjudicated for
applicability to the task (POSIX filesystem path traversal from Flask request data), and each warning is
mapped by hand to the documented defect (data/realworld/alert_adjudication.csv): `defect` (the vulnerable
flow), `related` (a flow the fix changes but whose exploitability at that sink is not established),
`unrelated`, or a site at the fixed revision. The adjudication was made after the runs, from the fix diffs
and code, without looking at arm decisions. Writes results/realworld.json and results/tables/realworld.md.
"""
import csv
import json
import sys

from neurosym.config import RESULTS, ROOT

ARMS = ("S", "D", "L", "E", "EC")
RW = ROOT / "data" / "realworld"


def decisions(run):
    d = RESULTS / "runs" / run
    return {a: {json.loads(l)["alert_id"]: json.loads(l)["decision"] for l in (d / f"decisions_{a}.jsonl").read_text().splitlines()}
            for a in ARMS}


def main(runs=("rw-vulnerable", "rw-fixed")):
    targets = list(csv.DictReader((RW / "target_adjudication.csv").open()))
    alerts = list(csv.DictReader((RW / "alert_adjudication.csv").open()))
    dec = {"vulnerable": decisions(runs[0]), "fixed": decisions(runs[1])}
    seen = {r: set(dec[r]["S"]) for r in dec}
    mapped = {r: {a["alert_id"] for a in alerts if a["revision"] == r} for r in dec}
    if seen != mapped:
        raise SystemExit(f"adjudication does not cover exactly the archived alerts: {seen} vs {mapped}")
    rows = []
    for t in targets:
        def keep(revision, roles):
            ids = [a["alert_id"] for a in alerts if a["target"] == t["target"] and a["revision"] == revision
                   and a["role"] in roles]
            return {arm: (any(dec[revision][arm][i] == "retain" for i in ids) if ids else None) for arm in ARMS}, len(ids)
        defect, n_def = keep("vulnerable", {"defect"})
        related, n_rel = keep("vulnerable", {"related"})
        fixed, n_fix = keep("fixed", {"fixed_defect_site", "related_fixed_site"})
        rows.append({**t, "defect_alerts": n_def, "related_alerts": n_rel, "fixed_site_alerts": n_fix,
                     "keeps_defect": defect, "keeps_related": related, "keeps_fixed_site": fixed})
    by_role = {}
    for a in alerts:
        k = f"{a['revision']}:{a['role']}"
        by_role.setdefault(k, {"alerts": 0, **{arm: 0 for arm in ARMS}})
        by_role[k]["alerts"] += 1
        for arm in ARMS:
            by_role[k][arm] += dec[a["revision"]][arm][a["alert_id"]] == "retain"
    applicable = [r for r in rows if r["applicable"] == "yes"]
    out = {"runs": list(runs), "targets": rows, "retained_by_role": by_role,
           "summary": {"screened_targets": len(rows), "applicable": len(applicable),
                       "s_reports_defect": sum(r["defect_alerts"] > 0 for r in applicable),
                       "s_reports_related_only": sum(r["defect_alerts"] == 0 and r["related_alerts"] > 0 for r in applicable),
                       "s_misses": sum(r["defect_alerts"] == 0 and r["related_alerts"] == 0 for r in applicable)}}
    (RESULTS / "realworld.json").write_text(json.dumps(out, indent=1))
    yn = lambda x: "-" if x is None else ("keep" if x else "drop")
    md = ["| Target | Applicable | Defect alerts | " + " | ".join(ARMS) + " |", "|---|---|---|" + "---|" * len(ARMS)]
    for r in rows:
        md.append(f"| {r['target']} | {r['applicable']} | {r['defect_alerts']} defect, {r['related_alerts']} related | "
                  + " | ".join(f"{yn(r['keeps_defect'][a])} / {yn(r['keeps_related'][a])} / {yn(r['keeps_fixed_site'][a])}"
                               for a in ARMS) + " |")
    md.append("\nCells: defect alert kept / related alert kept / fixed-revision site kept.\n")
    md.append("| Revision:role | Alerts | " + " | ".join(f"{a} kept" for a in ARMS) + " |")
    md.append("|---|---|" + "---|" * len(ARMS))
    for k, v in sorted(by_role.items()):
        md.append(f"| {k} | {v['alerts']} | " + " | ".join(str(v[a]) for a in ARMS) + " |")
    md.append(f"\n{json.dumps(out['summary'])}")
    (RESULTS / "tables").mkdir(parents=True, exist_ok=True)
    (RESULTS / "tables" / "realworld.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main(tuple(sys.argv[1:3]) if len(sys.argv) > 2 else ("rw-vulnerable", "rw-fixed"))
