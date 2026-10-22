"""Generate report tables (LaTeX + Markdown) from saved runs only. python -m neurosym.cli tables"""
import collections
import json

from . import diagnostics, owasp
from .config import RESULTS, ROOT

RUNS = RESULTS / "runs"
OUT_TEX, OUT_MD = ROOT / "report" / "tables", RESULTS / "tables"
ARMS = ("S", "D", "L", "E", "EC")
MAIN = [("OWASP test", "test-owasp-qcn", "qwen3-coder-next"), ("OWASP test", "test-owasp-q9b", "qwen3.5:9b"),
        ("Diagnostic held-out", "test-diag-qcn", "qwen3-coder-next"), ("Diagnostic held-out", "test-diag-q9b", "qwen3.5:9b")]


def _run(name):
    d = RUNS / name
    if not (d / "scores.json").exists():
        return None
    dec = {}
    for arm in ARMS:
        f = d / f"decisions_{arm}.jsonl"
        if f.exists():
            dec[arm] = {json.loads(l)["alert_id"]: json.loads(l) for l in f.read_text().splitlines()}
    return {"scores": json.loads((d / "scores.json").read_text()), "manifest": json.loads((d / "manifest.json").read_text()),
            "alerts": [json.loads(l) for l in (d / "baseline" / "alerts.jsonl").read_text().splitlines()], "decisions": dec}


def f3(x):
    return "--" if x is None else f"{x:.3f}"


def ci(c):
    return "" if not c else f" [{c[0]:.2f}, {c[1]:.2f}]"


def write(name, tex, md):
    OUT_TEX.mkdir(parents=True, exist_ok=True)
    OUT_MD.mkdir(parents=True, exist_ok=True)
    (OUT_TEX / f"{name}.tex").write_text(tex)
    (OUT_MD / f"{name}.md").write_text(md)


def subjects_table():
    rows = []
    for label, split, units in (("OWASP dev", "dev", owasp.load("dev")), ("OWASP test", "test", owasp.load("test"))):
        rows.append((label, len(units), sum(u.vulnerable for u in units), sum(not u.vulnerable for u in units),
                     len({u.family for u in units})))
    for label, split in (("Diagnostic dev", "dev"), ("Diagnostic held-out", "test")):
        units = diagnostics.subjects(split)
        rows.append((label, len(units), sum(u.gold for u in units), sum(not u.gold for u in units),
                     len({u.family for u in units})))
    tex = ["\\begin{tabular}{lrrrr}", "\\toprule", "Corpus & Units & Vuln. & Safe & Families \\\\", "\\midrule"]
    tex += [f"{r[0]} & {r[1]} & {r[2]} & {r[3]} & {r[4]} \\\\" for r in rows]
    tex += ["\\bottomrule", "\\end{tabular}"]
    md = "| Corpus | Units | Vulnerable | Safe | Families |\n|---|---|---|---|---|\n" + \
         "".join(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} |\n" for r in rows)
    write("subjects", "\n".join(tex) + "\n", md)


def main_table():
    tex = ["\\begin{tabular}{llrrrrrrrr}", "\\toprule",
           "Subjects / model & Arm & TP & FP & FN & Prec. & Rec. & F1 & TP ret. & FP rem. \\\\", "\\midrule"]
    md = ["| Subjects | Model | Arm | TP | FP | FN | TN | Precision | Recall | F1 | TP retention [95% CI] | FP removal [95% CI] | Wrongful supp. |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for label, run, model in MAIN:
        r = _run(run)
        if r is None:
            continue
        m, c = r["scores"]["metrics"], r["scores"].get("ci95", {})
        for i, arm in enumerate(ARMS):
            if arm not in m:
                continue
            v, cc = m[arm], c.get(arm, {})
            head = f"\\multirow{{5}}{{*}}{{\\shortstack[l]{{{label}\\\\\\texttt{{{model}}}}}}}" if i == 0 else ""
            tex.append(f"{head} & {arm} & {v['tp']} & {v['fp']} & {v['fn']} & {f3(v['precision'])} & {f3(v['recall'])} & "
                       f"{f3(v['f1'])} & {f3(v['tp_retention'])} & {f3(v['fp_removal'])} \\\\")
            md.append(f"| {label} | {model} | {arm} | {v['tp']} | {v['fp']} | {v['fn']} | {v['tn']} | {f3(v['precision'])} | "
                      f"{f3(v['recall'])} | {f3(v['f1'])} | {f3(v['tp_retention'])}{ci(cc.get('tp_retention'))} | "
                      f"{f3(v['fp_removal'])}{ci(cc.get('fp_removal'))} | {v['wrongful_suppressions']} |")
        tex.append("\\midrule")
    tex[-1] = "\\bottomrule"
    tex.append("\\end{tabular}")
    write("main", "\n".join(tex) + "\n", "\n".join(md) + "\n")


def unit_predictions(r):
    """unit -> arm -> predicted vulnerable (reported and at least one alert retained)."""
    pred = collections.defaultdict(dict)
    for arm, per in r["decisions"].items():
        kept = {a["unit"] for a in r["alerts"] if per[a["alert_id"]]["decision"] == "retain"}
        for a in r["alerts"]:
            pred[a["unit"]][arm] = a["unit"] in kept
    return pred


def diagnostic_table(run="test-diag-qcn"):
    r = _run(run)
    if r is None:
        return
    rows = diagnostics.manifest()
    pred = unit_predictions(r)
    fams = sorted({x["family"] for x in rows if x["split"] == "test"})
    lines_md = ["| Family | " + " | ".join(f"{a} pairs" for a in ARMS) + " | Wrongful (L/E/EC) |",
                "|---|" + "---|" * (len(ARMS) + 1)]
    tex = ["\\begin{tabular}{l" + "r" * len(ARMS) + "r}", "\\toprule",
           "Family & " + " & ".join(ARMS) + " & Wrongful L/E/EC \\\\", "\\midrule"]
    totals = collections.Counter()
    for fam in fams:
        members = [x for x in rows if x["split"] == "test" and x["family"] == fam]
        pairs = sorted({x["pair"] for x in members})
        cells, wrong = [], collections.Counter()
        for arm in ARMS:
            ok = 0
            for pid in pairs:
                both = [x for x in members if x["pair"] == pid]
                ok += all(pred.get(x["unit"], {}).get(arm, False) == (x["intended_vulnerable"] == "True") for x in both)
            cells.append(f"{ok}/{len(pairs)}")
            totals[arm] += ok
        for arm in ("L", "E", "EC"):
            wrong[arm] = sum(x["intended_vulnerable"] == "True" and x["unit"] in pred and not pred[x["unit"]].get(arm, True)
                             for x in members)
        w = "/".join(str(wrong[a]) for a in ("L", "E", "EC"))
        name = fam.replace("_", "\\_")
        tex.append(f"{name} & " + " & ".join(cells) + f" & {w} \\\\")
        lines_md.append(f"| {fam} | " + " | ".join(cells) + f" | {w} |")
    n_pairs = len({x["pair"] for x in rows if x["split"] == "test"})
    tex += ["\\midrule", "Total & " + " & ".join(f"{totals[a]}/{n_pairs}" for a in ARMS) + " & \\\\", "\\bottomrule", "\\end{tabular}"]
    lines_md.append("| **Total** | " + " | ".join(f"{totals[a]}/{n_pairs}" for a in ARMS) + " | |")
    gate = collections.Counter(d["gate"]["category"] or d["gate"]["check"] for d in r["decisions"]["EC"].values())
    lines_md.append("\nEC gate outcomes: " + ", ".join(f"{k}: {v}" for k, v in sorted(gate.items())))
    write("diagnostic_pairs", "\n".join(tex) + "\n", "\n".join(lines_md) + "\n")


def gate_table():
    md = ["| Run | E suppressions | EC accepted: structural | EC accepted: trusted contract | EC accepted: semantic judgment | Rejected by gate |",
          "|---|---|---|---|---|---|"]
    tex = ["\\begin{tabular}{lrrrrr}", "\\toprule", "Corpus, model & E supp. & Struct. & Contract & Semantic & Rejected \\\\", "\\midrule"]
    for label, run, model in MAIN:
        r = _run(run)
        if r is None or "EC" not in r["decisions"]:
            continue
        ec = r["decisions"]["EC"].values()
        supp = [d for d in ec if d["e_decision"] == "suppress"]
        cnt = collections.Counter(d["gate"]["category"] for d in supp if d["gate"]["suppress"])
        rej = sum(not d["gate"]["suppress"] for d in supp)
        short = {"qwen3-coder-next": "coder-next", "qwen3.5:9b": "9b"}[model]
        row = (f"{label.split()[0]}, {short}", len(supp), cnt["structural_check_passed"], cnt["trusted_contract_matched"],
               cnt["semantic_judgment_remaining"], rej)
        md.append("| " + " | ".join(str(x) for x in row) + " |")
        tex.append(" & ".join(str(x).replace("_", "\\_") for x in row) + " \\\\")
    tex += ["\\bottomrule", "\\end{tabular}"]
    write("gate", "\n".join(tex) + "\n", "\n".join(md) + "\n")


def resources_table():
    log = [json.loads(l) for l in (RESULTS / "llm_calls.jsonl").read_text().splitlines() if l.strip()]
    md = ["| Run | Model | Logical calls | Uncached | Prompt tokens | Completion tokens | LLM wall time (s) | Transport retries | Backend |",
          "|---|---|---|---|---|---|---|---|---|"]
    tex = ["\\begin{tabular}{llrrrrr}", "\\toprule", "Run & Model & Calls & Uncached & In tok. & Out tok. & Time (s) \\\\", "\\midrule"]
    for label, run, model in MAIN:
        r = _run(run)
        if r is None:
            continue
        m = r["manifest"]
        rows = [x for x in log if x["tag"].startswith(f"{run}:")]
        retries = sum(x.get("transport_retries") or 0 for x in rows)
        t = sum(v for k, v in m["timing_s"].items() if k.startswith("llm_"))
        md.append(f"| {run} | {model} | {m['llm']['calls']} | {m['llm']['uncached_calls']} | {m['llm']['prompt_tokens']:,} | "
                  f"{m['llm']['completion_tokens']:,} | {t:.0f} | {retries} | {', '.join(m['llm']['fingerprints'])} |")
        tex.append(f"{run.replace('test-', '')} & \\texttt{{{model}}} & {m['llm']['calls']} & {m['llm']['uncached_calls']} & "
                   f"{m['llm']['prompt_tokens']:,} & {m['llm']['completion_tokens']:,} & {t:.0f} \\\\")
    total_uncached = sum(not x["cached"] for x in log)
    total_tokens = sum((x["prompt_tokens"] or 0) + (x["completion_tokens"] or 0) for x in log if not x["cached"])
    md.append(f"\nWhole project to date (development + test + stability): {total_uncached} uncached requests, "
              f"{total_tokens:,} tokens (caps: 1,500 requests, 12M tokens).")
    tex += ["\\bottomrule", "\\end{tabular}"]
    write("resources", "\n".join(tex) + "\n", "\n".join(md) + "\n")


def main():
    subjects_table()
    main_table()
    diagnostic_table()
    gate_table()
    resources_table()
    print(f"tables written to {OUT_TEX} and {OUT_MD}")
