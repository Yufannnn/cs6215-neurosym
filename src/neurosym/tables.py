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


def gold_by_unit(run):
    if "owasp" in run:
        return {c.name: c.vulnerable for c in owasp.load("test")}
    return {u.unit: u.gold for u in diagnostics.subjects("test")}


def gate_table():
    """E suppressions by EC outcome; a rejection is correct if the alert's unit is vulnerable (alert level)."""
    md = ["| Run | E suppressions | EC accepted: structural | EC accepted: trusted contract | EC accepted: semantic judgment "
          "| Rejected: wrong E suppression (benefit) | Rejected: correct E suppression (cost) |",
          "|---|---|---|---|---|---|---|"]
    tex = ["\\begin{tabular}{lrrrrrr}", "\\toprule",
           "Corpus, model & E supp. & Struct. & Contract & Semantic & \\multicolumn{2}{c}{Rejected: wrong / correct} \\\\",
           "\\midrule"]
    for label, run, model in MAIN:
        r = _run(run)
        if r is None or "EC" not in r["decisions"]:
            continue
        gold = gold_by_unit(run)
        unit = {a["alert_id"]: a["unit"] for a in r["alerts"]}
        supp = [(k, d) for k, d in r["decisions"]["EC"].items() if d["e_decision"] == "suppress"]
        cnt = collections.Counter(d["gate"]["category"] for _, d in supp if d["gate"]["suppress"])
        rej_wrong = sum(not d["gate"]["suppress"] and gold[unit[k]] for k, d in supp)
        rej_right = sum(not d["gate"]["suppress"] and not gold[unit[k]] for k, d in supp)
        short = {"qwen3-coder-next": "coder-next", "qwen3.5:9b": "9b"}[model]
        row = (f"{label.split()[0]}, {short}", len(supp), cnt["structural_check_passed"], cnt["trusted_contract_matched"],
               cnt["semantic_judgment_remaining"], rej_wrong, rej_right)
        md.append("| " + " | ".join(str(x) for x in row) + " |")
        tex.append(" & ".join(str(x).replace("_", "\\_") for x in row) + " \\\\")
    tex += ["\\bottomrule", "\\end{tabular}"]
    write("gate", "\n".join(tex) + "\n", "\n".join(md) + "\n")


def resources_table():
    log = [json.loads(l) for l in (RESULTS / "llm_calls.jsonl").read_text().splitlines() if l.strip()]
    md = ["| Run | Model | Triage jobs (alerts x L,E) | Completion requests (incl. schema repair) | Uncached | Prompt tokens "
          "| Completion tokens | LLM wall time (s) | Transport retries | Backend |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    tex = ["\\begin{tabular}{llrrrrr}", "\\toprule", "Run & Model & Requests & Uncached & In tok. & Out tok. & Time (s) \\\\", "\\midrule"]
    for label, run, model in MAIN:
        r = _run(run)
        if r is None:
            continue
        m = r["manifest"]
        rows = [x for x in log if x["tag"].startswith(f"{run}:")]
        retries = sum(x.get("transport_retries") or 0 for x in rows)
        t = sum(v for k, v in m["timing_s"].items() if k.startswith("llm_"))
        md.append(f"| {run} | {model} | {2 * m['alerts']} | {m['llm']['calls']} | {m['llm']['uncached_calls']} | {m['llm']['prompt_tokens']:,} | "
                  f"{m['llm']['completion_tokens']:,} | {t:.0f} | {retries} | {', '.join(m['llm']['fingerprints'])} |")
        tex.append(f"{run.replace('test-', '')} & \\texttt{{{model}}} & {m['llm']['calls']} & {m['llm']['uncached_calls']} & "
                   f"{m['llm']['prompt_tokens']:,} & {m['llm']['completion_tokens']:,} & {t:.0f} \\\\")
    total_uncached = sum(not x["cached"] for x in log)
    total_tokens = sum((x["prompt_tokens"] or 0) + (x["completion_tokens"] or 0) for x in log if not x["cached"])
    md.append(f"\nWhole project to date (development + test + stability): {total_uncached} uncached requests, "
              f"{total_tokens:,} tokens (caps: 1,500 requests, 12M tokens).")
    tex += ["\\bottomrule", "\\end{tabular}"]
    write("resources", "\n".join(tex) + "\n", "\n".join(md) + "\n")


def status_table():
    """How each L/E decision came about: a valid first reply, a repaired reply, or a conservative fallback."""
    md = ["| Run | Arm | Valid reply | Valid after schema repair | Invalid after repair (kept) | No evidence (kept) | Transport error (kept) |",
          "|---|---|---|---|---|---|---|"]
    for label, run, model in MAIN:
        r = _run(run)
        if r is None:
            continue
        for arm in ("L", "E"):
            st = collections.Counter(d["status"] for d in r["decisions"][arm].values())
            row = (st["ok"], sum(v for k, v in st.items() if k.startswith("repaired_")),
                   sum(v for k, v in st.items() if k.startswith("invalid_")), st["no_evidence"] + st["over_input_budget"],
                   sum(v for k, v in st.items() if k.startswith("error:")))
            md.append(f"| {run} | {arm} | " + " | ".join(str(x) for x in row) + " |")
    (OUT_MD / "status.md").write_text("\n".join(md) + "\n")


def sensitivity_table():
    """OWASP metrics on the official labels and with the cases our review marked ambiguous left out."""
    import csv
    from . import scoring
    amb = {r["case"] for r in csv.DictReader((ROOT / "data" / "adjudications.csv").open()) if r["review"] == "ambiguous"}
    md = ["| Run | Arm | FP removal (official) | FP removal (ambiguous excluded) | TP retention (official) | TP retention (excluded) |",
          "|---|---|---|---|---|---|"]
    tex = ["\\begin{tabular}{llrrrr}", "\\toprule",
           "Model & Arm & \\multicolumn{2}{c}{FP removal} & \\multicolumn{2}{c}{TP retention} \\\\",
           " & & official & excl. & official & excl. \\\\", "\\midrule"]
    units_all = [{"unit": c.name, "gold": c.vulnerable, "family": c.family} for c in owasp.load("test")]
    for label, run, model in MAIN:
        if "owasp" not in run or (r := _run(run)) is None:
            continue
        reported = {a["unit"] for a in r["alerts"]}
        kept = {a: set(u) for a, u in r["scores"]["retained_units"].items()}
        sub = [u for u in units_all if u["unit"] not in amb]
        for arm in ARMS:
            o, x = scoring.metrics(units_all, reported, kept[arm]), scoring.metrics(sub, reported, kept[arm])
            fpo, fpx = f"{o['fp_removal']:.3f}", f"{x['fp_removal']:.3f}"
            md.append(f"| {run} | {arm} | {fpo} | {fpx} | {f3(o['tp_retention'])} | {f3(x['tp_retention'])} |")
            short = {"qwen3-coder-next": "coder-next", "qwen3.5:9b": "9b"}[model]
            tex.append(f"{short if arm == 'S' else ''} & {arm} & {fpo} & {fpx} & {f3(o['tp_retention'])} & {f3(x['tp_retention'])} \\\\")
        tex.append("\\midrule")
    tex[-1] = "\\bottomrule"
    tex.append("\\end{tabular}")
    md.append(f"\nExcluded as ambiguous ({len(amb)}): {', '.join(sorted(amb))}")
    write("sensitivity", "\n".join(tex) + "\n", "\n".join(md) + "\n")


def main():
    subjects_table()
    main_table()
    diagnostic_table()
    gate_table()
    resources_table()
    differences_table()
    status_table()
    sensitivity_table()
    print(f"tables written to {OUT_TEX} and {OUT_MD}")


PAIRS = (("E", "L"), ("EC", "E"), ("E", "D"), ("L", "D"))


def paired_differences(run, resamples=2000, seed=6215):
    """95% family-bootstrap CIs for differences between arms, using the same resamples for both arms."""
    import random
    from . import scoring
    r = _run(run)
    if r is None:
        return None
    s = json.loads((RUNS / run / "scores.json").read_text())
    kept = {arm: set(units) for arm, units in s["retained_units"].items()}
    corpus = "owasp" if "owasp" in run else "diag"
    if corpus == "owasp":
        units = [{"unit": c.name, "gold": c.vulnerable, "family": c.family} for c in owasp.load("test")]
    else:
        units = [{"unit": u.unit, "gold": u.gold, "family": u.family} for u in diagnostics.subjects("test")]
    reported = {a["unit"] for a in r["alerts"]}
    fams = {}
    for u in units:
        fams.setdefault(u["family"], []).append(u)
    keys = sorted(fams)
    rng = random.Random(seed)
    diffs = {p: {"fp_removal": [], "tp_retention": [], "wrongful_suppressions": []} for p in PAIRS}
    for _ in range(resamples):
        sample, rep, ret = [], set(), {a: set() for a in kept}
        for i, k in enumerate(rng.choice(keys) for _ in keys):
            for u in fams[k]:
                name = f"{u['unit']}#{i}"
                sample.append({**u, "unit": name})
                if u["unit"] in reported:
                    rep.add(name)
                for a in kept:
                    if u["unit"] in kept[a]:
                        ret[a].add(name)
        m = {a: scoring.metrics(sample, rep, ret[a]) for a in kept}
        for a, b in PAIRS:
            for k in diffs[(a, b)]:
                if m[a][k] is not None and m[b][k] is not None:
                    diffs[(a, b)][k].append(m[a][k] - m[b][k])
    point = {a: scoring.metrics(units, reported, kept[a]) for a in kept}
    out = {}
    for (a, b), per in diffs.items():
        out[f"{a}-{b}"] = {k: {"point": round(point[a][k] - point[b][k], 4),
                               "ci95": [round(sorted(v)[int(.025 * len(v))], 4), round(sorted(v)[int(.975 * len(v)) - 1], 4)] if len(v) >= 20 else None}
                           for k, v in per.items()}
    return out


def differences_table():
    md = ["| Run | Comparison | Δ FP removal [95% CI] | Δ TP retention [95% CI] | Δ wrongful suppressions [95% CI] |",
          "|---|---|---|---|---|"]
    for label, run, model in MAIN:
        d = paired_differences(run)
        if d is None:
            continue
        for comp, v in d.items():
            cells = []
            for k in ("fp_removal", "tp_retention", "wrongful_suppressions"):
                c = v[k]["ci95"]
                cells.append(f"{v[k]['point']:+.3f}" + (f" [{c[0]:+.3f}, {c[1]:+.3f}]" if c else ""))
            md.append(f"| {run} | {comp} | " + " | ".join(cells) + " |")
    (OUT_MD / "differences.md").write_text("\n".join(md) + "\n")
