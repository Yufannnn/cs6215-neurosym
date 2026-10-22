"""OWASP Benchmark for Python: path-traversal cases, flow-template families and the frozen dev/test split."""
import ast
import csv
import hashlib
import random
import re
from dataclasses import dataclass
from pathlib import Path

from .config import ROOT

BENCH = ROOT / "data" / "downloads" / "BenchmarkPython"
PINNED_REVISION = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
SPLIT_PATH = ROOT / "data" / "owasp_split.csv"
SEED = 6215
DEV_TARGET = 30
EXPOSED = {"BenchmarkTest00008"}  # inspected while planning


@dataclass(frozen=True)
class Case:
    name: str
    path: Path
    vulnerable: bool
    family: str
    split: str = ""


def _labels() -> dict[str, bool]:
    rows = csv.reader((BENCH / "expectedresults-0.1.csv").open())
    return {r[0]: r[2].strip() == "true" for r in rows
            if r and not r[0].startswith("#") and r[1].strip() == "pathtraver"}


def _defines(stmt: ast.stmt, var: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == var and isinstance(n.ctx, ast.Store)
               for n in ast.walk(stmt))


def flow_family(source: str) -> str:
    """Hash of the POST handler's param -> bar segment, with literals and test IDs abstracted."""
    post = next(f for f in ast.walk(ast.parse(source))
                if isinstance(f, ast.FunctionDef) and f.name.endswith("_post"))
    body = post.body
    last_param = max((i for i, s in enumerate(body) if _defines(s, "param")), default=-1)
    last_bar = max((i for i, s in enumerate(body) if _defines(s, "bar")), default=None)
    segment = "NOBAR" if last_bar is None else "\n".join(
        ast.unparse(s) for s in body[last_param + 1:last_bar + 1])
    segment = re.sub(r"'[^']*'|\"[^\"]*\"", "S", segment)
    segment = re.sub(r"BenchmarkTest\d+", "ID", segment)
    return hashlib.sha256(segment.encode()).hexdigest()[:10]


def compute_split() -> list[Case]:
    """Greedy seeded family split; the exposed case's family goes to development first."""
    labels = _labels()
    cases = [Case(n, BENCH / "testcode" / f"{n}.py", v,
                  flow_family((BENCH / "testcode" / f"{n}.py").read_text()))
             for n, v in sorted(labels.items())]
    families: dict[str, list[Case]] = {}
    for c in cases:
        families.setdefault(c.family, []).append(c)
    order = sorted(families)
    random.Random(SEED).shuffle(order)
    forced = [f for f in order if any(c.name in EXPOSED for c in families[f])]
    dev, n_dev = set(forced), sum(len(families[f]) for f in forced)
    for f in order:
        if n_dev >= DEV_TARGET:
            break
        if f not in dev and n_dev + len(families[f]) <= DEV_TARGET + 4:
            dev.add(f)
            n_dev += len(families[f])
    return [Case(c.name, c.path, c.vulnerable, c.family, "dev" if c.family in dev else "test")
            for c in cases]


def write_split(path: Path = SPLIT_PATH) -> None:
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case", "family", "split", "design_exposed"])
        for c in compute_split():
            w.writerow([c.name, c.family, c.split, c.name in EXPOSED])


def load(split: str) -> list[Case]:
    """Cases of one split, read from the frozen split file (labels from the pinned CSV)."""
    labels = _labels()
    rows = list(csv.DictReader(SPLIT_PATH.open()))
    return [Case(r["case"], BENCH / "testcode" / f"{r['case']}.py", labels[r["case"]], r["family"], r["split"])
            for r in rows if r["split"] == split]
