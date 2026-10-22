"""Real-world case studies from PyVul CWE-22 fix commits.

Screening is deterministic and uses feasibility only (never our method's results):
commit-level PyVul entry, CWE-22, repository clonable, fix changes non-test Python files, and the
changed files use Flask's request API (the frozen policy's threat model). Projects are taken in
descending order of qualifying commits (ties by name): at least 3 projects, more (up to 4) while there
are fewer than 6 target pairs; at most 10 pairs.
Every screened candidate is written to data/realworld/screening.csv with its decision and reason.
"""
import csv
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

from .config import ROOT
from .pipeline import Subject

PYVUL = ROOT / "data" / "downloads" / "PyVul" / "dataset"
CLONES = ROOT / "data" / "downloads" / "realworld"
SNAPSHOTS = ROOT / "data" / "realworld" / "snapshots"
SCREENING = ROOT / "data" / "realworld" / "screening.csv"
SELECTED = ROOT / "data" / "realworld" / "selected.json"
MIN_PROJECTS, MAX_PROJECTS, MIN_PAIRS, MAX_PAIRS = 3, 4, 6, 10
FLASK = re.compile(r"from flask import[^\n]*\brequest\b|flask\.request|import flask\b")


def _git(repo: Path, *args, check=True) -> str:
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if check and out.returncode:
        raise RuntimeError(out.stderr.strip()[:300])
    return out.stdout


def cwe22_commits() -> list[str]:
    commits = [l.strip() for l in (PYVUL / "commit_level_dataset.out").read_text().splitlines() if l.strip()]
    cmap = json.loads((PYVUL / "commits_cwe_map.json").read_text())
    return [c for c in commits if cmap.get(c) == "CWE-22"]


def target_functions(commit_url: str) -> list[str]:
    names = []
    for line in (PYVUL / "function_level_dataset.out").read_text().splitlines():
        if line.strip():
            rec = json.loads(line)
            if rec["commit"] == commit_url:
                names.append(rec["function_name"])
    return sorted(set(names))


def _clone(owner_repo: str) -> Path:
    dest = CLONES / owner_repo.replace("/", "__")
    if not dest.exists():
        CLONES.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout",
                        f"https://github.com/{owner_repo}.git", str(dest)], check=True, capture_output=True)
    return dest


def screen() -> list[dict]:
    rows, by_repo = [], {}
    for url in cwe22_commits():
        owner_repo, sha = "/".join(url.split("/")[3:5]), url.rsplit("/", 1)[-1]
        by_repo.setdefault(owner_repo, []).append((url, sha))
    qualifying = {}
    for owner_repo in sorted(by_repo):
        for url, sha in by_repo[owner_repo]:
            row = {"commit": url, "repo": owner_repo, "decision": "reject", "reason": "", "files": "", "targets": ""}
            try:
                repo = _clone(owner_repo)
                parent = _git(repo, "rev-parse", f"{sha}^").strip()
                changed = [f for f in _git(repo, "diff", "--name-only", parent, sha).split()
                           if f.endswith(".py") and not re.search(r"(^|/)(tests?|testing)/|test_", f)]
                if not changed:
                    row["reason"] = "fix changes no non-test Python file"
                else:
                    flask_files = [f for f in changed if FLASK.search(_git(repo, "show", f"{parent}:{f}", check=False))]
                    if not flask_files:
                        row["reason"] = "changed files do not use Flask request API (outside policy threat model)"
                    else:
                        row.update(decision="qualifies", reason="", files=";".join(flask_files),
                                   targets=";".join(target_functions(url)), parent=parent, fix=sha)
                        qualifying.setdefault(owner_repo, []).append(row)
            except Exception as e:  # unreachable repo or commit
                row["reason"] = f"not accessible: {str(e)[:120]}"
            rows.append(row)
    order = sorted(qualifying, key=lambda r: (-len(qualifying[r]), r))
    pairs, projects = 0, []
    for owner_repo in order:
        if len(projects) >= MAX_PROJECTS or (len(projects) >= MIN_PROJECTS and pairs >= MIN_PAIRS):
            for row in qualifying[owner_repo]:
                row["decision"], row["reason"] = "reject", "project cap reached"
            continue
        projects.append(owner_repo)
        for row in qualifying[owner_repo]:
            if pairs < MAX_PAIRS:
                row["decision"] = "selected"
                pairs += 1
            else:
                row["decision"], row["reason"] = "reject", "pair cap reached"
    SCREENING.parent.mkdir(parents=True, exist_ok=True)
    fields = ["commit", "repo", "decision", "reason", "files", "targets", "parent", "fix"]
    with SCREENING.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    selected = [r for r in rows if r["decision"] == "selected"]
    SELECTED.write_text(json.dumps(selected, indent=1))
    return rows


def materialize() -> None:
    """Write the changed files at the parent (vulnerable) and fix revisions as scan subjects."""
    for row in json.loads(SELECTED.read_text()):
        repo = _clone(row["repo"])
        for rev_name, rev in (("vulnerable", row["parent"]), ("fixed", row["fix"])):
            for f in row["files"].split(";"):
                text = _git(repo, "show", f"{rev}:{f}", check=False)
                if text:
                    out = SNAPSHOTS / row["repo"].replace("/", "__") / row["fix"][:10] / rev_name / f
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_text(text)


def subjects(split: str) -> list[Subject]:
    """split = vulnerable | fixed. Units are files; gold is None (labels are target-level, see realworld_eval)."""
    out = []
    for row in json.loads(SELECTED.read_text()):
        base = SNAPSHOTS / row["repo"].replace("/", "__") / row["fix"][:10] / split
        for f in row["files"].split(";"):
            p = base / f
            if p.exists():
                out.append(Subject(f"{row['repo']}@{row['fix'][:10]}:{f}", p, None, row["repo"], split, "realworld"))
    return out
