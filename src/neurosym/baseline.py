"""Arm S: run the frozen Semgrep CE rule and normalise its findings into canonical alerts."""
import hashlib
import json
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import ROOT

RULE = ROOT / "baseline" / "rules" / "cwe22-taint.yaml"
COMMUNITY_RULE = (ROOT / "data" / "downloads" / "semgrep-rules" / "python" / "flask" / "security"
                  / "injection" / "path-traversal-open.yaml")
SEMGREP = Path(sys.executable).with_name("semgrep")


@dataclass(frozen=True)
class Alert:
    alert_id: str      # stable: file hash + sink span + rule
    unit: str          # scoring unit (OWASP case name, fixture name, ...)
    path: str
    file_sha256: str
    rule_id: str
    line: int
    col: int
    end_line: int
    end_col: int


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def semgrep_version() -> str:
    return subprocess.run([str(SEMGREP), "--version"], capture_output=True, text=True).stdout.strip()


def environment(rule: Path = RULE) -> dict:
    return {"semgrep": semgrep_version(), "rule": str(rule.relative_to(ROOT)),
            "rule_sha256": sha256_file(rule), "python": platform.python_version(),
            "platform": f"{platform.system()} {platform.machine()}"}


def run(files: dict[str, Path], out_dir: Path, rule: Path = RULE, timeout: int = 60) -> list[Alert]:
    """Scan `files` (unit -> path); raw JSON is archived in out_dir. Returns alerts sorted by position."""
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = out_dir / f"semgrep-{rule.stem}.json"
    cmd = [str(SEMGREP), "scan", "--metrics=off", "--disable-version-check", "--quiet", "--no-git-ignore",
           "--config", str(rule), "--json", "--timeout", str(timeout), "-o", str(raw),
           *[str(p) for p in files.values()]]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1) or not raw.exists():
        raise RuntimeError(f"semgrep failed ({proc.returncode}): {proc.stderr[-2000:]}")
    data = json.loads(raw.read_text())
    if data.get("errors"):
        (out_dir / "semgrep-errors.json").write_text(json.dumps(data["errors"], indent=1))
    unit_of = {str(p.resolve()): u for u, p in files.items()}
    alerts = []
    for r in data["results"]:
        path = Path(r["path"]).resolve()
        digest = sha256_file(path)
        span = (r["start"]["line"], r["start"]["col"], r["end"]["line"], r["end"]["col"])
        aid = hashlib.sha256(f"{digest}:{span}:{r['check_id']}".encode()).hexdigest()[:16]
        alerts.append(Alert(aid, unit_of[str(path)], str(path), digest, r["check_id"].rsplit(".", 1)[-1], *span))
    alerts = sorted(set(alerts), key=lambda a: (a.unit, a.line, a.col))
    (out_dir / "alerts.jsonl").write_text("".join(json.dumps(asdict(a)) + "\n" for a in alerts))
    return alerts
