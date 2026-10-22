"""The frozen Semgrep rule fires exactly on the marked fixture lines."""
import re
from pathlib import Path

from neurosym import baseline

FIXTURE = Path(__file__).parent / "fixtures" / "rule_dev.py"


def test_rule_matches_fixture_expectations(tmp_path):
    lines = FIXTURE.read_text().splitlines()
    marked = {i + 1: m.group(1) for i, l in enumerate(lines) if (m := re.search(r"\S.*#\s*EXPECT: (alert|none)", l))
              and not l.lstrip().startswith(("#", '"', "Each"))}
    got = {a.line for a in baseline.run({"fx": FIXTURE}, tmp_path)}
    assert {l for l, e in marked.items() if e == "alert"} <= got
    assert not ({l for l, e in marked.items() if e == "none"} & got)
    assert got <= set(marked), f"unmarked alerts: {sorted(got - set(marked))}"


def test_environment_is_pinned():
    env = baseline.environment()
    assert env["semgrep"] == "1.182.1" and len(env["rule_sha256"]) == 64
