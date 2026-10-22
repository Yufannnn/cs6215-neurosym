"""Deterministic extraction and arm D: every supported construct has a positive and a negative test."""
from neurosym.refine import deterministic

from helpers import record_for


def facts(tmp_path, body):
    r = record_for(tmp_path, body)
    return r, r["facts"], deterministic(r)["decision"]


def test_direct_flow_is_tainted(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    name = request.args.get("f")
    return open(os.path.join(ROOT, name)).read()
""")
    assert f["sink_value_kind"] == "tainted" and f["complete"] and d == "retain"


def test_constant_overwrite_suppressed(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    name = request.args.get("f")
    name = "fixed.txt"
    return open(os.path.join(ROOT, name)).read()
""")
    assert f["sink_value_kind"] in ("constant", "trusted") and d == "suppress"


def test_tainted_overwrite_after_constant_retained(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    name = "fixed.txt"
    name = request.cookies.get("f", name)
    return open(os.path.join(ROOT, name)).read()
""")
    assert f["sink_value_kind"] == "tainted" and d == "retain"


def test_infeasible_branch_pruned(tmp_path):
    r, f, d = facts(tmp_path, """
def handler():
    param = request.args.get("f")
    flag = 'This should never happen'
    if 'should' not in flag:
        bar = param
    else:
        bar = 'safe'
    return open(os.path.join(ROOT, bar)).read()
""")
    assert f["sink_value_kind"] in ("constant", "trusted") and f["pruned_tainted_definitions"] and d == "suppress"


def test_feasible_branch_kept(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    param = request.args.get("f")
    flag = 'This should never happen'
    if 'should' in flag:
        bar = param
    else:
        bar = 'safe'
    return open(os.path.join(ROOT, bar)).read()
""")
    assert f["sink_value_kind"] == "tainted" and d == "retain"


def test_match_on_constant(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    param = request.form.get("f")
    guess = 'ABC'[1]
    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case _:
            bar = param
    return os.path.exists(f'{ROOT}/{bar}')
""")
    assert f["sink_value_kind"] == "trusted" and d == "suppress"


def test_match_on_attacker_value(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    param = request.form.get("f")
    match param:
        case 'A':
            bar = 'a'
        case _:
            bar = param
    return os.path.exists(f'{ROOT}/{bar}')
""")
    assert f["sink_value_kind"] == "tainted" and d == "retain"


def test_list_container_constant_element(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    param = request.form.get("f")
    lst = []
    lst.append('safe')
    lst.append(param)
    lst.append('moresafe')
    lst.pop(0)
    bar = lst[1]
    return open(os.path.join(ROOT, bar)).read()
""")
    assert f["sink_value_kind"] in ("constant", "trusted") and d == "suppress"


def test_list_container_tainted_element(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    param = request.form.get("f")
    lst = ['safe', param, 'moresafe']
    lst.pop(0)
    bar = lst[0]
    return open(os.path.join(ROOT, bar)).read()
""")
    assert f["sink_value_kind"] == "tainted" and d == "retain"


def test_loop_break_carries_taint(tmp_path):
    # regression: states leaving a loop through break must rejoin (BenchmarkTest00618 shape)
    _, f, d = facts(tmp_path, """
def handler():
    param = ''
    for name in request.headers.keys():
        if name.lower() in ('host', 'accept'):
            continue
        param = name
        break
    return open(os.path.join(ROOT, param)).read()
""")
    assert f["sink_value_kind"] == "tainted" and d == "retain"


def test_loop_over_constants_reaches_fixpoint(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    name = 'index.txt'
    for c in ['a.txt', 'b.txt']:
        if c.startswith('b'):
            name = c
            break
    return open(os.path.join(ROOT, name)).read()
""")
    assert f["sink_value_kind"] in ("constant", "trusted") and f["complete"] and d == "suppress"


def test_non_converging_loop_is_incomplete(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    name = ''
    for c in ['a', 'b', 'c', 'd', 'e', 'f']:
        name = name + c
    return open(os.path.join(ROOT, name)).read()
""")
    assert not f["complete"] and d == "retain"


def test_container_alias_is_incomplete(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    parts = []
    alias = parts
    alias.append(request.args.get("f"))
    parts.append('x')
    return open(os.path.join(ROOT, parts[0])).read()
""")
    assert not f["complete"] and d == "retain"


def test_dict_get_with_attacker_key_is_constant(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    files = {'a': 'a.txt', 'b': 'b.txt'}
    return open(os.path.join(ROOT, files.get(request.args.get('k'), 'a.txt'))).read()
""")
    assert f["sink_value_kind"] in ("constant", "trusted") and d == "suppress"


def test_unknown_function_is_not_assumed_safe(tmp_path):
    _, f, d = facts(tmp_path, """
def helper(x):
    return x

def handler():
    return open(helper(request.args.get('f'))).read()
""")
    assert f["sink_value_kind"] == "tainted" and d == "retain"


def test_sound_containment_commonpath(tmp_path):
    r, f, d = facts(tmp_path, """
def handler():
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f")))
    if os.path.commonpath([ROOT, target]) != ROOT:
        abort(403)
    return open(target).read()
""")
    assert f["containment_guards"] and d == "suppress"


def test_sound_containment_startswith_sep(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f")))
    if not target.startswith(ROOT + os.sep):
        return "no"
    return open(target).read()
""")
    assert f["containment_guards"] and d == "suppress"


def test_prefix_without_separator_is_not_containment(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f")))
    if not target.startswith(ROOT):
        abort(403)
    return open(target).read()
""")
    assert not f["containment_guards"] and d == "retain"


def test_containment_without_normalization_is_not_sound(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    target = os.path.join(ROOT, request.args.get("f"))
    if os.path.commonpath([ROOT, target]) != ROOT:
        abort(403)
    return open(target).read()
""")
    assert not f["containment_guards"] and d == "retain"


def test_resolve_then_is_relative_to(tmp_path):
    _, f, d = facts(tmp_path, """
def handler():
    target = (pathlib.Path(ROOT) / request.args.get("f")).resolve()
    if not target.is_relative_to(ROOT):
        abort(403)
    return target.read_text()
""")
    assert f["containment_guards"] and d == "suppress"


def test_guard_on_different_value_does_not_cover(tmp_path):
    r, f, d = facts(tmp_path, """
def handler():
    other = os.path.realpath(os.path.join(ROOT, request.args.get("g")))
    if os.path.commonpath([ROOT, other]) != ROOT:
        abort(403)
    return open(os.path.join(ROOT, request.args.get("f"))).read()
""")
    assert d == "retain" and not f["containment_guards"]
    assert all(not c["covers_all_tainted_flows"] for c in r["path_conditions_at_sink"])


def test_non_exiting_reject_branch_is_not_a_guard(tmp_path):
    r, f, d = facts(tmp_path, """
def handler():
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f")))
    if not target.startswith(ROOT + os.sep):
        print("suspicious")
    return open(target).read()
""")
    assert r["path_conditions_at_sink"] == [] and d == "retain"


def test_later_tainted_overwrite_invalidates_guard(tmp_path):
    r, f, d = facts(tmp_path, """
def handler():
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f")))
    if not target.startswith(ROOT + os.sep):
        abort(403)
    target = os.path.join(ROOT, request.args.get("g"))
    return open(target).read()
""")
    assert d == "retain" and not f["containment_guards"]
    assert all(not c["guards_sink_value"] for c in r["path_conditions_at_sink"])


def test_one_guarded_branch_does_not_cover_alternative(tmp_path):
    r, f, d = facts(tmp_path, """
def handler():
    if request.args.get("mode") == "user":
        target = os.path.realpath(os.path.join(ROOT, request.args.get("f")))
        if not target.startswith(ROOT + os.sep):
            abort(403)
    else:
        target = os.path.join(ROOT, request.args.get("legacy"))
    return open(target).read()
""")
    assert d == "retain" and not f["containment_guards"]
    assert all(not c["covers_all_tainted_flows"] for c in r["path_conditions_at_sink"])


def test_blocklist_guard_covers_but_is_not_sound(tmp_path):
    r, f, d = facts(tmp_path, """
def handler():
    bar = request.headers.get("f")
    if '../' in bar:
        return "no"
    fileName = f'{ROOT}/{bar}'
    return open(fileName, 'wb')
""")
    guard = r["path_conditions_at_sink"][0]
    assert guard["covers_all_tainted_flows"] and not f["containment_guards"] and d == "retain"


def test_record_has_no_benchmark_ids(tmp_path):
    r = record_for(tmp_path, """
def BenchmarkTest00123_post():
    name = request.args.get("BenchmarkTest00123")
    return open(name).read()
""")
    import json
    assert "BenchmarkTest" not in json.dumps({k: r[k] for k in r if k != "file_sha256"})
