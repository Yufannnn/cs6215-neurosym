"""Unit-level metrics for every arm, with family-cluster bootstrap intervals."""
import random

SEED = 6215
RESAMPLES = 2000
METRICS = ("precision", "recall", "f1", "tp_retention", "fp_removal")


def _ratio(a, b):
    return a / b if b else None


def metrics(units: list[dict], reported: set, retained: set) -> dict:
    """units: [{"unit", "gold" (bool), "family"}]. reported = A (baseline units), retained = R (arm units)."""
    gold = {u["unit"] for u in units if u["gold"]}
    neg = {u["unit"] for u in units if u["gold"] is False}
    a, r = reported & (gold | neg), retained & (gold | neg)
    tp, fp = len(r & gold), len(r & neg)
    fn, tn = len(gold - r), len(neg - r)
    p, rec = _ratio(tp, tp + fp), _ratio(tp, len(gold))
    return {"units": len(gold | neg), "positives": len(gold), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": p, "recall": rec,
            "f1": (2 * p * rec / (p + rec)) if p is not None and rec is not None and p + rec else (0.0 if p is not None and rec is not None else None),
            "tp_retention": _ratio(len(r & gold), len(a & gold)),
            "fp_removal": _ratio(len((a - r) - gold), len(a - gold)),
            "wrongful_suppressions": len((a - r) & gold),
            "baseline_recall": _ratio(len(a & gold), len(gold))}


def bootstrap(units, reported, retained_by_arm: dict, resamples=RESAMPLES, seed=SEED) -> dict:
    """95% percentile intervals, resampling whole families; differences vs S use the same resamples."""
    families = {}
    for u in units:
        families.setdefault(u["family"], []).append(u)
    keys = sorted(families)
    rng = random.Random(seed)
    draws = {arm: {m: [] for m in METRICS} for arm in retained_by_arm}
    for _ in range(resamples):
        picked = [families[k] for k in (rng.choice(keys) for _ in keys)]
        # rename duplicated units so a family drawn twice counts twice
        sample, rep, ret = [], set(), {arm: set() for arm in retained_by_arm}
        for i, fam in enumerate(picked):
            for u in fam:
                name = f"{u['unit']}#{i}"
                sample.append({**u, "unit": name})
                if u["unit"] in reported:
                    rep.add(name)
                for arm, kept in retained_by_arm.items():
                    if u["unit"] in kept:
                        ret[arm].add(name)
        for arm in retained_by_arm:
            m = metrics(sample, rep, ret[arm])
            for k in METRICS:
                if m[k] is not None:
                    draws[arm][k].append(m[k])
    out = {}
    for arm, per in draws.items():
        out[arm] = {k: _interval(v) for k, v in per.items()}
    return out


def _interval(vals):
    if len(vals) < 20:
        return None
    vals = sorted(vals)
    return [round(vals[int(0.025 * len(vals))], 4), round(vals[int(0.975 * len(vals)) - 1], 4)]


def score(units: list[dict], alerts: list[dict], decisions: dict) -> dict:
    """decisions: arm -> alert_id -> {"decision": retain|suppress, ...}. A unit is retained if any alert is."""
    reported = {a["unit"] for a in alerts}
    retained = {arm: {a["unit"] for a in alerts if per[a["alert_id"]]["decision"] == "retain"}
                for arm, per in decisions.items()}
    table = {arm: metrics(units, reported, kept) for arm, kept in retained.items()}
    for arm, m in table.items():  # scorer identity: recall = baseline recall x TP retention
        if m["recall"] is not None and m["tp_retention"] is not None:
            assert abs(m["recall"] - m["baseline_recall"] * m["tp_retention"]) < 1e-9, arm
        assert retained[arm] <= reported, f"{arm} retained a unit the baseline never reported"
    ci = bootstrap(units, reported, retained) if len({u["family"] for u in units}) > 1 else {}
    return {"metrics": table, "ci95": ci, "retained_units": {k: sorted(v) for k, v in retained.items()}}
