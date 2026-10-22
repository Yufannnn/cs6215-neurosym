"""Generate the diagnostic paired programs and their manifest. Run: python data/diagnostics/build.py

Development and held-out pairs use disjoint semantic families. Held-out families follow the plan's
test families (docs/plan/PLAN.md section 7), each realised with two different code shapes. Reference
patterns: Python os.path / pathlib documentation, Flask send_from_directory documentation, and the
OWASP Path Traversal guidance. Intended labels are re-checked mechanically by neurosym.diagnostics.validate().
"""
import csv
import textwrap
from pathlib import Path

HERE = Path(__file__).parent
HEADER = '''import os
import os.path
import pathlib
import re
import hashlib
import logging
import urllib.parse
from flask import request, abort, send_file, send_from_directory

ROOT = "/srv/app/files"
log = logging.getLogger(__name__)

'''

# (split, family, pair, member, label, reference, body)
SPECS = []


def pair(split, family, idx, reference, vuln_body, safe_body):
    SPECS.append((split, family, f"{family}{idx}", "vuln", True, reference, vuln_body))
    SPECS.append((split, family, f"{family}{idx}", "safe", False, reference, safe_body))


# ---------------------------------------------------------------- held-out (test) families
pair("test", "checked_vs_original", 1, "os.path.realpath/commonpath + urllib.parse.unquote docs", '''
def handler():
    name = request.args.get("f", "")
    candidate = os.path.realpath(os.path.join(ROOT, name))
    if os.path.commonpath([ROOT, candidate]) != ROOT:
        abort(403)
    return open(os.path.join(ROOT, urllib.parse.unquote(name))).read()
''', '''
def handler():
    name = request.args.get("f", "")
    candidate = os.path.realpath(os.path.join(ROOT, name))
    if os.path.commonpath([ROOT, candidate]) != ROOT:
        abort(403)
    return open(candidate).read()
''')
pair("test", "checked_vs_original", 2, "pathlib Path.resolve/is_relative_to + urllib.parse.unquote docs", '''
def handler():
    name = request.form.get("doc", "")
    resolved = (pathlib.Path(ROOT) / name).resolve()
    if not resolved.is_relative_to(ROOT):
        abort(400)
    return (pathlib.Path(ROOT) / urllib.parse.unquote(name)).read_text()
''', '''
def handler():
    name = request.form.get("doc", "")
    resolved = (pathlib.Path(ROOT) / name).resolve()
    if not resolved.is_relative_to(ROOT):
        abort(400)
    return resolved.read_text()
''')
pair("test", "overwrite", 1, "OWASP Path Traversal (use server-chosen names)", '''
def handler():
    name = request.args.get("f", "")
    if name.endswith(".txt"):
        name = "default.txt"
    return open(os.path.join(ROOT, name)).read()
''', '''
def handler():
    name = request.args.get("f", "")
    use_default = True
    if use_default:
        name = "default.txt"
    return open(os.path.join(ROOT, name)).read()
''')
pair("test", "overwrite", 2, "OWASP Path Traversal (use server-chosen names)", '''
def handler():
    report = "summary.txt"
    report = request.cookies.get("report", report)
    return os.path.exists(f"{ROOT}/{report}")
''', '''
def handler():
    report = request.cookies.get("report", "summary.txt")
    report = "summary.txt"
    return os.path.exists(f"{ROOT}/{report}")
''')
pair("test", "guard_other_value", 1, "os.path.commonpath docs", '''
def handler():
    name = request.args.get("f", "")
    other = request.args.get("g", "")
    checked = os.path.realpath(os.path.join(ROOT, other))
    if os.path.commonpath([ROOT, checked]) != ROOT:
        abort(403)
    return open(os.path.realpath(os.path.join(ROOT, name))).read()
''', '''
def handler():
    name = request.args.get("f", "")
    checked = os.path.realpath(os.path.join(ROOT, name))
    if os.path.commonpath([ROOT, checked]) != ROOT:
        abort(403)
    return open(checked).read()
''')
pair("test", "guard_other_value", 2, "os.path.realpath docs", '''
def handler():
    path = os.path.realpath(os.path.join(ROOT, request.form.get("p", "")))
    backup = os.path.realpath(os.path.join(ROOT, request.form.get("b", "")))
    if not path.startswith(ROOT + os.sep):
        abort(403)
    os.remove(backup)
    return "ok"
''', '''
def handler():
    path = os.path.realpath(os.path.join(ROOT, request.form.get("p", "")))
    if not path.startswith(ROOT + os.sep):
        abort(403)
    os.remove(path)
    return "ok"
''')
pair("test", "reject_exits", 1, "OWASP Path Traversal (reject, do not continue)", '''
def handler():
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f", "")))
    if not target.startswith(ROOT + os.sep):
        log.warning("suspicious path %s", target)
    return open(target).read()
''', '''
def handler():
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f", "")))
    if not target.startswith(ROOT + os.sep):
        log.warning("suspicious path %s", target)
        return "forbidden", 403
    return open(target).read()
''')
pair("test", "reject_exits", 2, "OWASP Path Traversal (reject, do not continue)", '''
def handler():
    target = os.path.abspath(os.path.join(ROOT, request.headers.get("X-Doc", "")))
    if os.path.commonpath([ROOT, target]) != ROOT:
        print("outside root")
    return os.path.exists(target)
''', '''
def handler():
    target = os.path.abspath(os.path.join(ROOT, request.headers.get("X-Doc", "")))
    if os.path.commonpath([ROOT, target]) != ROOT:
        raise PermissionError("outside root")
    return os.path.exists(target)
''')
pair("test", "send_from_directory_base", 1, "Flask send_from_directory docs (directory must be trusted)", '''
def handler():
    folder = request.args.get("dir", "public")
    return send_from_directory(folder, "index.html")
''', '''
def handler():
    name = request.args.get("f", "index.html")
    return send_from_directory(ROOT, name)
''')
pair("test", "send_from_directory_base", 2, "Flask send_from_directory / send_file docs", '''
def handler():
    name = request.args.get("f", "index.html")
    return send_file(os.path.join(ROOT, name))
''', '''
def handler():
    name = request.args.get("f", "index.html")
    return send_from_directory(ROOT, name)
''')
pair("test", "prefix_confusion", 1, "os.path.commonpath docs (string prefix is not containment)", '''
def handler():
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f", "")))
    if not target.startswith(ROOT):
        abort(403)
    return open(target).read()
''', '''
def handler():
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f", "")))
    if os.path.commonpath([ROOT, target]) != ROOT:
        abort(403)
    return open(target).read()
''')
pair("test", "prefix_confusion", 2, "os.path.commonpath docs (string prefix is not containment)", '''
def handler():
    target = os.path.abspath(os.path.join(ROOT, request.form.get("f", "")))
    if target.startswith(ROOT):
        return os.path.exists(target)
    return False
''', '''
def handler():
    target = os.path.abspath(os.path.join(ROOT, request.form.get("f", "")))
    if target.startswith(ROOT + os.sep):
        return os.path.exists(target)
    return False
''')
pair("test", "canonicalize_only", 1, "os.path.realpath docs", '''
def handler():
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f", "")))
    return open(target).read()
''', '''
def handler():
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f", "")))
    if os.path.commonpath([ROOT, target]) != ROOT:
        abort(404)
    return open(target).read()
''')
pair("test", "canonicalize_only", 2, "os.path.normpath docs", '''
def handler():
    target = os.path.normpath(os.path.join(ROOT, request.args.get("f", "")))
    return os.listdir(target)
''', '''
def handler():
    target = os.path.normpath(os.path.join(ROOT, request.args.get("f", "")))
    if not target.startswith(ROOT + os.sep):
        abort(404)
    return os.listdir(target)
''')
pair("test", "absolute_join", 1, "os.path.join docs (absolute component discards the prefix)", '''
def handler():
    name = request.args.get("f", "")
    if ".." in name:
        abort(400)
    return open(os.path.join(ROOT, name)).read()
''', '''
def handler():
    name = request.args.get("f", "")
    if ".." in name:
        abort(400)
    return open(f"{ROOT}/{name}").read()
''')
pair("test", "absolute_join", 2, "os.path.join docs (absolute component discards the prefix)", '''
def handler():
    name = request.form.get("f", "")
    if "../" in name:
        abort(400)
    return pathlib.Path(os.path.join(ROOT, name)).read_text()
''', '''
def handler():
    name = request.form.get("f", "").lstrip("/")
    if ".." in name:
        abort(400)
    return pathlib.Path(os.path.join(ROOT, name)).read_text()
''')
pair("test", "alternate_branch", 1, "OWASP Path Traversal (validate every input path)", '''
def handler():
    if request.args.get("mode") == "user":
        target = os.path.realpath(os.path.join(ROOT, request.args.get("f", "")))
        if not target.startswith(ROOT + os.sep):
            abort(403)
    else:
        target = os.path.join(ROOT, request.args.get("legacy", ""))
    return open(target).read()
''', '''
def handler():
    if request.args.get("mode") == "user":
        target = os.path.realpath(os.path.join(ROOT, request.args.get("f", "")))
    else:
        target = os.path.realpath(os.path.join(ROOT, request.args.get("legacy", "")))
    if not target.startswith(ROOT + os.sep):
        abort(403)
    return open(target).read()
''')
pair("test", "alternate_branch", 2, "OWASP Path Traversal (validate every input path)", '''
def handler():
    name = request.args.get("f", "")
    target = os.path.abspath(os.path.join(ROOT, name))
    if request.args.get("strict") and os.path.commonpath([ROOT, target]) != ROOT:
        abort(403)
    return os.path.exists(target)
''', '''
def handler():
    name = request.args.get("f", "")
    target = os.path.abspath(os.path.join(ROOT, name))
    if os.path.commonpath([ROOT, target]) != ROOT:
        abort(403)
    return os.path.exists(target)
''')
pair("test", "named_sanitizer", 1, "OWASP Path Traversal (filtering '../' is bypassable)", '''
def sanitize(name):
    return name.replace("../", "")


def handler():
    return open(os.path.join(ROOT, sanitize(request.args.get("f", "")))).read()
''', '''
def sanitize(name):
    base = os.path.basename(name)
    if base in ("", ".", ".."):
        abort(400)
    return base


def handler():
    return open(os.path.join(ROOT, sanitize(request.args.get("f", "")))).read()
''')
pair("test", "named_sanitizer", 2, "OWASP Path Traversal (filtering '../' is bypassable)", '''
def handler():
    name = request.args.get("f", "").replace("../", "")
    return open(os.path.join(ROOT, name)).read()
''', '''
def handler():
    name = os.path.basename(request.args.get("f", ""))
    if name in ("", ".", ".."):
        abort(400)
    return open(os.path.join(ROOT, name)).read()
''')
pair("test", "unreachable_flow", 1, "Python language reference (constant conditions)", '''
DEBUG = True


def handler():
    name = "index.txt"
    if DEBUG:
        name = request.args.get("f", "index.txt")
    return open(os.path.join(ROOT, name)).read()
''', '''
def handler():
    debug = False
    name = "index.txt"
    if debug:
        name = request.args.get("f", "index.txt")
    return open(os.path.join(ROOT, name)).read()
''')
pair("test", "unreachable_flow", 2, "Python language reference (match statement)", '''
def handler():
    kind = request.args.get("kind", "a")
    match kind:
        case "a":
            name = "a.txt"
        case _:
            name = request.args.get("f", "b.txt")
    return os.path.exists(os.path.join(ROOT, name))
''', '''
def handler():
    kind = "a"
    match kind:
        case "a":
            name = "a.txt"
        case _:
            name = request.args.get("f", "b.txt")
    return os.path.exists(os.path.join(ROOT, name))
''')
pair("test", "container_alias", 1, "Python data model (mutation through aliases)", '''
def handler():
    parts = []
    alias = parts
    alias.append(request.args.get("f", ""))
    parts.append("x")
    return open(os.path.join(ROOT, parts[0])).read()
''', '''
def handler():
    parts = [request.args.get("f", "")]
    parts = ["fixed.txt"]
    return open(os.path.join(ROOT, parts[0])).read()
''')
pair("test", "container_alias", 2, "Python data model (dict update)", '''
def handler():
    box = {"f": "fixed.txt"}
    box.update(request.args)
    return open(os.path.join(ROOT, box["f"])).read()
''', '''
def handler():
    box = {"f": request.args.get("f", "")}
    box["f"] = "fixed.txt"
    return open(os.path.join(ROOT, box["f"])).read()
''')

# ---------------------------------------------------------------- development families (disjoint)
pair("dev", "allowlist", 1, "OWASP Path Traversal (allow-list input)", '''
BLOCKED = {"secret.txt", "passwd"}


def handler():
    name = request.args.get("f", "")
    if name in BLOCKED:
        abort(403)
    return open(os.path.join(ROOT, name)).read()
''', '''
ALLOWED = {"a.txt", "b.txt"}


def handler():
    name = request.args.get("f", "")
    if name not in ALLOWED:
        abort(403)
    return open(os.path.join(ROOT, name)).read()
''')
pair("dev", "dict_lookup", 1, "OWASP Path Traversal (map input to server-side names)", '''
FILES = {"a": "a.txt", "b": "b.txt"}


def handler():
    key = request.args.get("k", "a")
    return open(os.path.join(ROOT, FILES.get(key, key))).read()
''', '''
def handler():
    files = {"a": "a.txt", "b": "b.txt"}
    key = request.args.get("k", "a")
    return open(os.path.join(ROOT, files.get(key, "a.txt"))).read()
''')
pair("dev", "ternary", 1, "Python language reference (conditional expressions)", '''
def handler():
    name = request.args.get("f", "")
    target = name if name else "index.txt"
    return open(os.path.join(ROOT, target)).read()
''', '''
def handler():
    name = request.args.get("f", "")
    target = name if False else "index.txt"
    return open(os.path.join(ROOT, target)).read()
''')
pair("dev", "basename", 1, "os.path.basename docs", '''
def handler():
    base = os.path.basename(request.args.get("f", ""))
    return os.path.exists(os.path.join(ROOT, base))
''', '''
def handler():
    base = os.path.basename(request.args.get("f", ""))
    if base in ("", ".", ".."):
        return False
    return os.path.exists(os.path.join(ROOT, base))
''')
pair("dev", "decode_order", 1, "urllib.parse.unquote docs", '''
def handler():
    raw = request.args.get("f", "")
    if ".." in raw:
        abort(400)
    name = urllib.parse.unquote(raw)
    return open(f"{ROOT}/{name}").read()
''', '''
def handler():
    name = urllib.parse.unquote(request.args.get("f", ""))
    target = os.path.realpath(os.path.join(ROOT, name))
    if os.path.commonpath([ROOT, target]) != ROOT:
        abort(400)
    return open(target).read()
''')
pair("dev", "exception_flow", 1, "Python language reference (try statement)", '''
def handler():
    try:
        name = request.args["f"]
    except KeyError:
        name = "index.txt"
    return open(os.path.join(ROOT, name)).read()
''', '''
def handler():
    try:
        name = int(request.args["n"])
        name = "index.txt"
    except (KeyError, ValueError):
        name = "index.txt"
    return open(os.path.join(ROOT, name)).read()
''')
pair("dev", "resolve_order", 1, "pathlib PurePath.is_relative_to docs (lexical)", '''
def handler():
    target = pathlib.Path(ROOT) / request.args.get("f", "")
    if not target.is_relative_to(ROOT):
        abort(403)
    return target.read_text()
''', '''
def handler():
    target = (pathlib.Path(ROOT) / request.args.get("f", "")).resolve()
    if not target.is_relative_to(ROOT):
        abort(403)
    return target.read_text()
''')
pair("dev", "loop_source", 1, "OWASP Benchmark header-name idiom", '''
def handler():
    name = "index.txt"
    for header in request.headers.keys():
        if header.lower().startswith("x-file"):
            name = header
            break
    return open(os.path.join(ROOT, name)).read()
''', '''
def handler():
    name = "index.txt"
    for candidate in ["a.txt", "b.txt"]:
        if candidate.startswith("b"):
            name = candidate
            break
    return open(os.path.join(ROOT, name)).read()
''')
pair("dev", "lstrip_join", 1, "os.path.join docs", '''
def handler():
    name = request.args.get("f", "").lstrip("/")
    return open(os.path.join(ROOT, name)).read()
''', '''
def handler():
    name = request.args.get("f", "").lstrip("/")
    target = os.path.realpath(os.path.join(ROOT, name))
    if os.path.commonpath([ROOT, target]) != ROOT:
        abort(403)
    return open(target).read()
''')
pair("dev", "numeric_id", 1, "OWASP Path Traversal (use indirect identifiers)", '''
def handler():
    doc = request.args.get("id", "0")
    return open(f"{ROOT}/{doc}.txt").read()
''', '''
def handler():
    doc = int(request.args.get("id", "0"))
    return open(f"{ROOT}/{doc}.txt").read()
''')
pair("dev", "hashed_name", 1, "OWASP Path Traversal (server-generated names)", '''
def handler():
    name = request.args.get("f", "")
    return open(f"{ROOT}/{name}.cache").read()
''', '''
def handler():
    name = request.args.get("f", "")
    digest = hashlib.sha256(name.encode()).hexdigest()
    return open(f"{ROOT}/{digest}.cache").read()
''')
pair("dev", "regex_anchor", 1, "re.match / re.fullmatch docs", '''
def handler():
    name = request.args.get("f", "")
    if not re.match(r"[A-Za-z0-9_]+", name):
        abort(400)
    return open(os.path.join(ROOT, name)).read()
''', '''
def handler():
    name = request.args.get("f", "")
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        abort(400)
    return open(os.path.join(ROOT, name)).read()
''')


def main():
    rows = []
    for split, family, pair_id, member, label, ref, body in SPECS:
        out = HERE / split / f"{pair_id}_{member}.py"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(HEADER + textwrap.dedent(body).lstrip("\n"))
        rows.append({"unit": f"{pair_id}_{member}", "split": split, "family": family, "pair": pair_id,
                     "member": member, "intended_vulnerable": label, "reference": ref,
                     "path": str(out.relative_to(HERE))})
    with (HERE / "manifest.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} programs")


if __name__ == "__main__":
    main()
