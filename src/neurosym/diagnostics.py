"""Diagnostic paired programs: loading and mechanical label validation.

validate() executes each handler (our own fixtures only) against traversal payloads with every
filesystem call stubbed out, and records the paths those calls would touch. A program is
vulnerable iff some payload makes a recorded path leave ROOT. This is ground-truth checking only;
the analyzer never uses it.
"""
import builtins
import contextlib
import csv
import importlib.util
import io
import itertools
import os
import os.path
import pathlib
import posixpath
import sys
import types

from .config import ROOT as REPO
from .pipeline import Subject

DIAG = REPO / "data" / "diagnostics"
ROOT_DIR = "/srv/app/files"
CWD = "/srv/app"
PAYLOADS = ["../secret.txt", "../../etc/passwd", "/etc/passwd", "..", "....//....//etc/passwd",
            "%2e%2e%2fsecret", "..%2f..%2fsecret", "a/../../secret", "../files_secret/x",
            "x-file/../../../etc/passwd", "ok.txt"]
CONTROL = ["", "user", "1", "a", "b"]
PRIMARY = {"f", "p", "doc", "report", "dir", "X-Doc", "id", "k", "n"}
SECONDARY = {"g", "b", "legacy"}
PATH_KEYS = PRIMARY | SECONDARY
MODES = ["all", "primary", "secondary"]  # which inputs carry the payload; the others get a benign name


def manifest() -> list[dict]:
    return list(csv.DictReader((DIAG / "manifest.csv").open()))


def subjects(split: str) -> list[Subject]:
    return [Subject(r["unit"], DIAG / r["path"], r["intended_vulnerable"] == "True", r["family"], split, "diag")
            for r in manifest() if r["split"] == split]


class _Abort(Exception):
    pass


class _Multi:
    """Attacker-controlled multidict: path-like keys carry the payload, others a control value."""

    def __init__(self, payload, control, mode="all"):
        self.payload, self.control, self.mode = payload, control, mode

    def _val(self, key):
        if key not in PATH_KEYS:
            return self.control
        carries = self.mode == "all" or (key in PRIMARY) == (self.mode == "primary")
        return self.payload if carries else "ok.txt"

    def get(self, key, default=None, type=None):
        return self._val(key)

    def __getitem__(self, key):
        return self._val(key)

    def getlist(self, key):
        return [self._val(key)]

    def keys(self):
        return sorted(PATH_KEYS) + ["mode", "strict", "kind", self.payload]

    def __iter__(self):
        return iter(self.keys())


class _Request:
    def set(self, payload, control, mode="all"):
        for attr in ("args", "form", "values", "cookies", "headers"):
            setattr(self, attr, _Multi(payload, control, mode))


def _escapes(path) -> bool:
    p = posixpath.normpath(posixpath.join(CWD, os.fspath(path)))
    return not (p == ROOT_DIR or p.startswith(ROOT_DIR + "/"))


def _safe_join(directory, name):
    joined = posixpath.normpath(posixpath.join(CWD, directory, name))
    base = posixpath.normpath(posixpath.join(CWD, directory))
    return joined if joined.startswith(base + "/") and not posixpath.isabs(name) else None


def validate(path: pathlib.Path) -> dict:
    """Run the program's handler under all payload/control combinations; report escaping accesses."""
    touched, request = [], _Request()
    flask = types.ModuleType("flask")
    flask.request = request
    flask.abort = lambda *a, **k: (_ for _ in ()).throw(_Abort())

    def send_file(p, *a, **k):
        touched.append(p)
        return "file"

    def send_from_directory(directory, name, *a, **k):
        target = _safe_join(directory, name)
        if target is not None:
            touched.append(target)
        return "file"

    flask.send_file, flask.send_from_directory = send_file, send_from_directory
    record = lambda p, *a, **k: touched.append(p) or io.StringIO("data")
    patches = [(builtins, "open", record), (os.path, "exists", lambda p: touched.append(p) or True),
               (os, "listdir", lambda p: touched.append(p) or []), (os, "remove", lambda p: touched.append(p)),
               (pathlib.Path, "read_text", lambda self, *a, **k: touched.append(self) or "data"),
               (pathlib.Path, "exists", lambda self, *a, **k: touched.append(self) or True),
               (pathlib.Path, "open", lambda self, *a, **k: touched.append(self) or io.StringIO("data"))]
    saved_flask = sys.modules.get("flask")
    originals = [(obj, name, getattr(obj, name)) for obj, name, _ in patches]
    escaped, errors, runs = [], 0, 0
    try:
        sys.modules["flask"] = flask
        spec = importlib.util.spec_from_file_location(f"diag_{path.stem}", path)
        mod = importlib.util.module_from_spec(spec)
        for obj, name, fn in patches:
            setattr(obj, name, fn)
        spec.loader.exec_module(mod)
        for payload, control, mode in itertools.product(PAYLOADS, CONTROL, MODES):
            request.set(payload, control, mode)
            touched.clear()
            runs += 1
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    mod.handler()
            except (_Abort, PermissionError):
                pass
            except Exception:
                errors += 1
            if any(_escapes(p) for p in touched):
                escaped.append((payload, control, mode))
    finally:
        for obj, name, fn in originals:
            setattr(obj, name, fn)
        if saved_flask is None:
            sys.modules.pop("flask", None)
        else:
            sys.modules["flask"] = saved_flask
    return {"vulnerable": bool(escaped), "witnesses": escaped[:3], "runs": runs, "errors": errors}


def validate_all() -> list[dict]:
    out = []
    for r in manifest():
        res = validate(DIAG / r["path"])
        out.append({"unit": r["unit"], "split": r["split"], "intended": r["intended_vulnerable"] == "True",
                    "validated": res["vulnerable"], "agree": res["vulnerable"] == (r["intended_vulnerable"] == "True"),
                    "witness": res["witnesses"][:1], "errors": res["errors"], "runs": res["runs"]})
    return out
