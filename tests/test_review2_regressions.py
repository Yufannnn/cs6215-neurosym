"""Second post-review correctness regressions (docs/review/gptpro-2026-10-25, docs/decisions.md D-R2).

Each unsafe program escapes /srv/app/files for some request input, yet review-correction-1 reported complete
evidence and arm D suppressed the warning. The first six are the reviewer's witnesses; the rest are holes of the
same kinds found while fixing them. Every case is first executed with a recording `open`, so the test also
checks that the program really escapes. The safe programs check that the fixes kept the intended precision.
"""
import posixpath
import types

import pytest

from neurosym.refine import deterministic, gate

from helpers import HEADER, record_for

UNSAFE = {
    # reviewer witnesses
    "keyword_mutation": """
def handler():
    cfg = {'f': 'ok.txt'}
    cfg.update(f=request.args['f'])
    name = cfg['f']
    return open(ROOT + '/' + name)
""",
    "boolop_operand_value": """
def handler():
    mode = 'upload' or 'fallback'
    name = request.args['f']
    if mode != 'upload':
        name = 'ok.txt'
    return open(ROOT + '/' + name)
""",
    "boolop_skipped_side_effect": """
def handler():
    names = [request.args['f']]
    False and names.append('ok.txt')
    name = names[-1]
    return open(ROOT + '/' + name)
""",
    "duplicate_dict_key": """
def handler():
    cfg = {'f': 'ok.txt', 'f': request.args['f']}
    name = cfg['f']
    return open(ROOT + '/' + name)
""",
    "shadowed_normalizer": """
from os.path import abspath
def abspath(value):
    return value
def handler():
    candidate = abspath(ROOT + '/' + request.args['f'])
    if not candidate.startswith(ROOT + '/'):
        abort(403)
    return open(candidate)
""",
    "custom_resolve": """
class Candidate:
    def __init__(self, value):
        self.value = value
    def resolve(self):
        return self.value
def handler():
    candidate = Candidate(ROOT + '/' + request.args['f']).resolve()
    if not candidate.startswith(ROOT + '/'):
        abort(403)
    return open(candidate)
""",
    # found while fixing them
    "ifexp_skipped_side_effect": """
def handler():
    names = [request.args['f']]
    names.append('ok.txt') if request.args.get('x') else None
    name = names[-1]
    return open(ROOT + '/' + name)
""",
    "boolop_undecided_side_effect": """
def handler():
    names = [request.args['f']]
    request.args.get('x') and names.append('ok.txt')
    name = names[-1]
    return open(ROOT + '/' + name)
""",
    "abstract_key_after_match": """
def handler():
    cfg = {'f': 'ok.txt', request.args['k']: request.args['f']}
    name = cfg['f']
    return open(ROOT + '/' + name)
""",
    "duplicate_key_get": """
def handler():
    cfg = {'f': 'ok.txt', 'f': request.args['f']}
    name = cfg.get('f')
    return open(ROOT + '/' + name)
""",
    "update_from_unmodelled_call": """
def load():
    return {'f': request.args['f']}
def handler():
    cfg = {'f': 'ok.txt'}
    cfg.update(load())
    name = cfg['f']
    return open(ROOT + '/' + name)
""",
    "shadowed_abort": """
def abort(code):
    return None
def handler():
    candidate = os.path.abspath(os.path.join(ROOT, request.args['f']))
    if not candidate.startswith(ROOT + '/'):
        abort(403)
    return open(candidate)
""",
}

INPUTS = {"f": "../../secret.txt", "k": "f", "x": ""}


def _escapes(body: str) -> bool:
    """Run the handler with a recording open() and a raising abort(), as the reviewer's witnesses do."""
    visited = []

    def record_open(path, *args, **kwargs):
        visited.append(str(path))

    def flask_abort(*args):
        raise PermissionError("aborted")

    env = {"__name__": "case", "request": types.SimpleNamespace(args=INPUTS), "abort": flask_abort}
    exec(HEADER.replace("from flask import request, abort\n", "") + body, env)
    env["open"] = record_open
    env["os"] = types.SimpleNamespace(path=posixpath, sep="/")  # POSIX semantics on any host (see protocol)
    try:
        env["handler"]()
    except PermissionError:
        return False
    return any(posixpath.commonpath(["/srv/app/files", posixpath.normpath(p)]) != "/srv/app/files" for p in visited)


@pytest.mark.parametrize("name", sorted(UNSAFE))
def test_unsafe_program_is_not_suppressed(tmp_path, name):
    assert _escapes(UNSAFE[name]), f"{name}: the program should reach a path outside the root"
    r = record_for(tmp_path, UNSAFE[name])
    assert deterministic(r)["decision"] == "retain", (name, r["facts"])


SAFE = {
    "boolop_constant_choice": """
def handler():
    mode = 'upload' or 'fallback'
    name = request.args['f']
    if mode == 'upload':
        name = 'ok.txt'
    return open(ROOT + '/' + name)
""",
    "duplicate_key_safe_last": """
def handler():
    cfg = {'f': request.args['f'], 'f': 'ok.txt'}
    name = cfg['f']
    return open(ROOT + '/' + name)
""",
    "pathlib_resolve_containment": """
def handler():
    candidate = (pathlib.Path(ROOT) / request.args['f']).resolve()
    if not candidate.is_relative_to(ROOT):
        abort(403)
    return open(candidate)
""",
    "abspath_containment": """
def handler():
    candidate = os.path.abspath(os.path.join(ROOT, request.args['f']))
    if not candidate.startswith(ROOT + '/'):
        abort(403)
    return open(candidate)
""",
}


@pytest.mark.parametrize("name", sorted(SAFE))
def test_safe_program_still_suppressed(tmp_path, name):
    assert not _escapes(SAFE[name]), f"{name}: the program should stay inside the root"
    r = record_for(tmp_path, SAFE[name])
    assert r["facts"]["complete"] and deterministic(r)["decision"] == "suppress", (name, r["facts"])


@pytest.mark.parametrize("name", ["shadowed_normalizer", "custom_resolve"])
def test_gate_does_not_match_a_contract_on_a_fake_normalizer(tmp_path, name):
    """The reviewer's EC check: a suppression citing the guard must not pass as trusted_contract_matched."""
    r = record_for(tmp_path, UNSAFE[name])
    guard = r["path_conditions_at_sink"][0]["id"]
    verdict = {"decision": "suppress", "reason_kind": "guarded_path_confinement", "evidence_node_ids": [guard],
               "obligations": {k: {"status": "holds", "node_ids": [guard]}
                               for k in ("control", "flow", "confinement", "coverage")}}
    assert r["facts"]["containment_guards"] == []
    assert gate(r, verdict)["category"] != "trusted_contract_matched"
