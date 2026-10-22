import ast
import textwrap

from neurosym import evidence

HEADER = "import os\nimport os.path\nimport pathlib\nfrom flask import request, abort\nROOT = '/srv/app/files'\n"
SINKS = {"open", "os.path.exists", "os.remove", "os.listdir"}


def record_for(tmp_path, body: str, name="case.py") -> dict:
    """Write a handler module and extract evidence for its first sink (as Semgrep would report it)."""
    src = HEADER + textwrap.dedent(body)
    path = tmp_path / name
    path.write_text(src)
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            fn = ast.unparse(n.func)
            if fn in SINKS:
                arg = n.args[0]
            elif isinstance(n.func, ast.Attribute) and n.func.attr in ("read_text", "exists") and fn != "os.path.exists":
                arg = n.func.value
            else:
                continue
            return evidence.extract(path, arg.lineno, arg.col_offset + 1, arg.end_lineno, arg.end_col_offset + 1)
    raise AssertionError("no sink in snippet")
