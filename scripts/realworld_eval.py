"""Target-level evaluation of the real-world runs (rw-vulnerable, rw-fixed). Writes results/realworld.json + table.

A target is the set of functions PyVul marks for the fix commit (fallback: functions touched by the
fix diff in the parent revision). Baseline coverage = S reports an alert inside a target function at
the vulnerable revision. Retention is evaluated only on covered targets. At the fixed revision an
alert left inside a target function counts as a negative for that defect only; every other alert is
unlabeled and only counted.
"""
import ast
import json
import re
import subprocess
from pathlib import Path

from neurosym.config import RESULTS, ROOT
from neurosym import realworld

ARMS = ("S", "D", "L", "E", "EC")


def enclosing(path, line):
    tree = ast.parse(Path(path).read_text())
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno <= line <= n.end_lineno:
            if best is None or n.lineno >= best.lineno:
                best = n
    return best.name if best else None


def diff_functions(row, f):
    repo = realworld._clone(row["repo"])
    out = subprocess.run(["git", "-C", str(repo), "diff", "-U0", row["parent"], row["fix"], "--", f],
                         capture_output=True, text=True).stdout
    lines = [int(m.group(1)) for m in re.finditer(r"^@@ -(\d+)", out, re.M)]
    path = realworld.SNAPSHOTS / row["repo"].replace("/", "__") / row["fix"][:10] / "vulnerable" / f
    return {enclosing(path, l) for l in lines if path.exists()} - {None}


def load(run):
    d = RESULTS / "runs" / run
    alerts = [json.loads(l) for l in (d / "baseline" / "alerts.jsonl").read_text().splitlines()]
    dec = {a: {json.loads(l)["alert_id"]: json.loads(l)["decision"] for l in (d / f"decisions_{a}.jsonl").read_text().splitlines()}
           for a in ARMS}
    return alerts, dec


def main():
    selected = json.loads(realworld.SELECTED.read_text())
    vuln_alerts, vuln_dec = load("rw-vulnerable")
    fixed_alerts, fixed_dec = load("rw-fixed")
    targets, rows = {}, []
    for row in selected:
        key = f"{row['repo']}@{row['fix'][:10]}"
        names = set(filter(None, row["targets"].split(";")))
        source = "pyvul"
        if not names:
            names = set().union(*[diff_functions(row, f) for f in row["files"].split(";")])
            source = "diff"
        targets[key] = names

        def in_target(a):
            return a["unit"].startswith(key + ":") and enclosing(a["path"], a["line"]) in names
        v = [a for a in vuln_alerts if in_target(a)]
        fx = [a for a in fixed_alerts if in_target(a)]
        rec = {"target": key, "repo": row["repo"], "functions": sorted(names), "target_source": source,
               "s_reports_vulnerable": bool(v), "s_reports_fixed": bool(fx),
               "vulnerable_alerts": len(v), "fixed_alerts": len(fx)}
        for arm in ARMS:
            rec[f"{arm}_retains_vulnerable"] = any(vuln_dec[arm][a["alert_id"]] == "retain" for a in v) if v else None
            rec[f"{arm}_retains_fixed"] = any(fixed_dec[arm][a["alert_id"]] == "retain" for a in fx) if fx else None
        rows.append(rec)
    other = {}
    for name, alerts, dec in (("vulnerable", vuln_alerts, vuln_dec), ("fixed", fixed_alerts, fixed_dec)):
        unl = [a for a in alerts if not any(a["unit"].startswith(k + ":") and enclosing(a["path"], a["line"]) in t
                                            for k, t in targets.items())]
        other[name] = {"unlabeled_alerts": len(unl),
                       **{f"{arm}_retained": sum(dec[arm][a["alert_id"]] == "retain" for a in unl) for arm in ARMS}}
    out = {"targets": rows, "unlabeled": other,
           "coverage": {"targets": len(rows), "s_reports_vulnerable": sum(r["s_reports_vulnerable"] for r in rows)}}
    (RESULTS / "realworld.json").write_text(json.dumps(out, indent=1))
    md = ["| Target | S reports (vuln / fixed) | " + " | ".join(f"{a} keeps vuln / fixed" for a in ARMS) + " |",
          "|---|---|" + "---|" * len(ARMS)]
    yn = lambda x: "-" if x is None else ("yes" if x else "no")
    for r in rows:
        md.append(f"| {r['target']} | {yn(r['s_reports_vulnerable'])} / {yn(r['s_reports_fixed'])} | " +
                  " | ".join(f"{yn(r[f'{a}_retains_vulnerable'])} / {yn(r[f'{a}_retains_fixed'])}" for a in ARMS) + " |")
    md.append(f"\nUnlabeled alerts outside targets: {json.dumps(other)}")
    (RESULTS / "tables").mkdir(parents=True, exist_ok=True)
    (RESULTS / "tables" / "realworld.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
