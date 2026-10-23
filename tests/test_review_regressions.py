"""Post-review correctness regressions (docs/review/gptpro-2026-10-23, docs/decisions.md D-R1).

Each unsafe program below escapes /srv/app/files for some request input. The frozen extractor reported
complete evidence and arm D suppressed the warning; the corrected extractor must keep it. The first seven
are the reviewer's witnesses; the rest are holes of the same kind found while fixing them. The safe
programs check that the fixes did not remove the recognizers' intended precision.
"""
import pytest

from neurosym.refine import deterministic, gate

from helpers import record_for

UNSAFE = {
    # reviewer witnesses
    "reversed_commonpath": """
def handler():
    candidate = os.path.abspath(request.args['f'])
    if os.path.commonpath([ROOT, candidate]) != candidate:
        abort(403)
    return os.listdir(candidate)
""",
    "attacker_root": """
def handler():
    root = request.args['dir']
    candidate = os.path.abspath(request.args['f'])
    if not candidate.startswith(root + '/'):
        abort(403)
    return open(candidate)
""",
    "loop_else_break": """
def handler():
    name = request.args['f']
    for i in [1]:
        break
    else:
        name = 'ok.txt'
    return open(ROOT + '/' + name)
""",
    "return_through_finally": """
def handler():
    name = 'ok.txt'
    try:
        if request.args['mode']:
            name = request.args['f']
            return 'done'
    finally:
        open(ROOT + '/' + name)
""",
    "chained_alias": """
def handler():
    a = b = ['ok.txt']
    b.append(request.args['f'])
    name = a[-1]
    return open(ROOT + '/' + name)
""",
    "nested_alias": """
def handler():
    inner = ['ok.txt']
    outer = [inner]
    inner.append(request.args['f'])
    name = outer[0][-1]
    return open(ROOT + '/' + name)
""",
    # same classes, found during the correction
    "handler_sees_nested_state": """
def handler():
    name = 'ok.txt'
    try:
        if request.args.get('m'):
            name = request.args['f']
            int(request.args['n'])
            name = 'ok.txt'
    except ValueError:
        return open(ROOT + '/' + name)
""",
    "exception_through_finally": """
def handler():
    name = 'ok.txt'
    try:
        name = request.args['f']
        int(name)
        name = 'ok.txt'
    finally:
        open(ROOT + '/' + name)
""",
    "suppressing_with": """
def handler():
    name = 'ok.txt'
    with contextlib.suppress(ValueError):
        name = request.args['f']
        int(name)
        name = 'ok.txt'
    return open(ROOT + '/' + name)
""",
    "kwargs_parameter": """
def handler(**kw):
    return open(ROOT + '/' + kw['f'])
""",
    "varargs_parameter": """
def handler(*parts):
    return open(ROOT + '/' + parts[0])
""",
    "match_class_capture": """
def handler():
    match request.args['f']:
        case str(x):
            return open(ROOT + '/' + x)
""",
    "match_sequence_capture": """
def handler():
    match request.args.getlist('f'):
        case [x, *rest]:
            return open(ROOT + '/' + x)
""",
    "global_mutated_elsewhere": """
CFG = {'f': 'ok.txt'}
def setter():
    CFG['f'] = request.args['f']
def handler():
    return open(ROOT + '/' + CFG['f'])
""",
    "global_mutated_locally": """
CFG = ['ok.txt']
def handler():
    CFG.append(request.args['f'])
    return open(ROOT + '/' + CFG[-1])
""",
    "module_helper_reads_request": """
def get_name():
    return request.args['f']
def handler():
    return open(ROOT + '/' + get_name())
""",
    "nested_helper_reads_request": """
def handler():
    def get():
        return request.args['f']
    name = get()
    return open(ROOT + '/' + name)
""",
    "nested_helper_mutates_capture": """
def handler():
    names = ['ok.txt']
    def fill():
        names.append(request.args['f'])
    fill()
    return open(ROOT + '/' + names[-1])
""",
    "container_passed_to_callee": """
def handler():
    store = {'f': 'ok.txt'}
    fill(store, request.args['f'])
    return open(ROOT + '/' + store['f'])
""",
    "object_filled_by_callee": """
def handler():
    conf = configparser.ConfigParser()
    load(conf, request.args['f'])
    return open(ROOT + '/' + conf.get('s', 'k'))
""",
    "container_stored_in_container": """
def handler():
    inner = ['ok.txt']
    holder = {}
    holder['x'] = inner
    holder['x'].append(request.args['f'])
    return open(ROOT + '/' + inner[-1])
""",
    "break_through_finally": """
def handler():
    name = 'ok.txt'
    for i in [1, 2]:
        try:
            name = request.args['f']
            break
        finally:
            pass
    else:
        name = 'ok.txt'
    return open(ROOT + '/' + name)
""",
}

SAFE = {
    "commonpath_root_role": """
def handler():
    candidate = os.path.abspath(os.path.join(ROOT, request.args['f']))
    if os.path.commonpath([ROOT, candidate]) != ROOT:
        abort(403)
    return open(candidate)
""",
    "startswith_trusted_root": """
def handler():
    candidate = os.path.realpath(os.path.join(ROOT, request.args['f']))
    if not candidate.startswith(ROOT + os.sep):
        abort(403)
    return open(candidate)
""",
    "startswith_local_constant_root": """
def handler():
    base = '/srv/app/files'
    candidate = os.path.abspath(os.path.join(base, request.args['f']))
    if not candidate.startswith(base + '/'):
        abort(403)
    return open(candidate)
""",
    "loop_else_without_break": """
def handler():
    name = request.args['f']
    for i in [1]:
        pass
    else:
        name = 'ok.txt'
    return open(ROOT + '/' + name)
""",
    "try_finally_without_sink": """
def handler():
    name = request.args['f']
    try:
        x = 1
    finally:
        y = 2
    name = 'ok.txt'
    return open(ROOT + '/' + name)
""",
    "join_list_of_strings": """
def handler():
    parts = ['a', 'b']
    name = '/'.join(parts)
    return open(ROOT + '/' + name)
""",
}


@pytest.mark.parametrize("name", sorted(UNSAFE))
def test_unsafe_program_is_not_suppressed(tmp_path, name):
    r = record_for(tmp_path, UNSAFE[name])
    assert deterministic(r)["decision"] == "retain", (name, r["facts"])


@pytest.mark.parametrize("name", sorted(SAFE))
def test_safe_program_still_suppressed(tmp_path, name):
    r = record_for(tmp_path, SAFE[name])
    assert r["facts"]["complete"] and deterministic(r)["decision"] == "suppress", (name, r["facts"])


def test_attacker_root_guard_is_not_sound_containment(tmp_path):
    r = record_for(tmp_path, UNSAFE["attacker_root"])
    assert r["facts"]["containment_guards"] == []


def test_gate_is_a_dependency_filter_not_value_identity(tmp_path):
    """Documents the EC limitation (review finding 4): a guard on an ancestor of the sink value passes the
    structural check even though a later transformation breaks confinement. Such a suppression is accepted
    only as semantic_judgment_remaining, never as a matched trusted contract, and D keeps the warning."""
    r = record_for(tmp_path, """
def handler():
    target = os.path.abspath(os.path.join(ROOT, request.args['f']))
    if not target.startswith(ROOT + '/'):
        abort(403)
    name = target + '/../../secret.txt'
    return open(name)
""")
    guard = r["path_conditions_at_sink"][0]["id"]
    verdict = {"decision": "suppress", "reason_kind": "guarded_path_confinement", "evidence_node_ids": [guard],
               "obligations": {k: {"status": "holds", "node_ids": [guard]}
                               for k in ("control", "flow", "confinement", "coverage")}}
    g = gate(r, verdict)
    assert deterministic(r)["decision"] == "retain"
    assert g["suppress"] and g["category"] == "semantic_judgment_remaining"
