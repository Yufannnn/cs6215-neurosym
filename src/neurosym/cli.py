"""Command line: python -m neurosym.cli <command> ...

  split                                  regenerate data/owasp_split.csv (deterministic)
  run --subjects owasp:dev --name NAME   run the arms on a subject set (test data requires protocol-freeze)
  tables                                 regenerate report tables from saved runs
"""
import argparse
import json

from . import owasp, pipeline
from .pipeline import Subject


def load_subjects(spec: str, allow_unfrozen: bool = False, tag: str = "protocol-freeze") -> list[Subject]:
    corpus, _, split = spec.partition(":")
    if corpus == "owasp":
        if split == "test" and not allow_unfrozen:
            pipeline.require_frozen(tag)
        return [Subject(c.name, c.path, c.vulnerable, c.family, c.split, "owasp") for c in owasp.load(split)]
    if corpus == "diag":
        from . import diagnostics
        if split == "test" and not allow_unfrozen:
            pipeline.require_frozen(tag)
        return diagnostics.subjects(split)
    if corpus == "realworld":
        from . import realworld
        return realworld.subjects(split)
    raise SystemExit(f"unknown subject set {spec}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="neurosym")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("split")
    r = sub.add_parser("run")
    r.add_argument("--subjects", required=True)
    r.add_argument("--name", required=True)
    r.add_argument("--arms", default=",".join(pipeline.ARMS))
    r.add_argument("--model", default="qwen3-coder-next")
    r.add_argument("--replicate", type=int, default=0)
    r.add_argument("--offline", action="store_true", help="replay cached responses only; never call the API")
    r.add_argument("--workers", type=int, default=3)
    r.add_argument("--correction", action="store_true",
                   help=f"post-review correction run: name must start with corr-; checked against {pipeline.CORRECTION_TAG}")
    sub.add_parser("tables")
    args = p.parse_args(argv)

    if args.cmd == "split":
        owasp.write_split()
    elif args.cmd == "run":
        if args.correction != args.name.startswith("corr-"):
            raise SystemExit("correction runs, and only they, are named corr-*")
        subjects = load_subjects(args.subjects, tag=pipeline.CORRECTION_TAG if args.correction else "protocol-freeze")
        res = pipeline.run(args.name, subjects, arms=tuple(args.arms.split(",")), model=args.model,
                           replicate=args.replicate, offline=args.offline, workers=args.workers)
        m = res["scores"].get("metrics", {})
        for arm, v in m.items():
            fmt = lambda x: "  n/a" if x is None else f"{x:5.3f}"
            print(f"{arm:3s} TP {v['tp']:3d} FP {v['fp']:3d} FN {v['fn']:3d} TN {v['tn']:3d}  "
                  f"P {fmt(v['precision'])} R {fmt(v['recall'])} F1 {fmt(v['f1'])}  "
                  f"TPret {fmt(v['tp_retention'])} FPrem {fmt(v['fp_removal'])}")
        print(json.dumps(res["manifest"]["llm"]), f"\n-> {res['out']}")
    elif args.cmd == "tables":
        from . import tables
        tables.main()


if __name__ == "__main__":
    main()
