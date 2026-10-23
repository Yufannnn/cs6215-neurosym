"""Deterministic evidence for one alert: an intraprocedural value analysis over the enclosing function.

Values are sets of abstract elements: concrete Python constants (including small lists/dicts/paths
whose elements may themselves be abstract), TRUSTED (untainted configuration value, e.g. a module
constant), UNKNOWN (unmodelled, might hide anything) and TAINT (attacker-controlled under the policy).
Statements are walked in order with constant folding; provably infeasible branches are pruned.
Loops, exceptional edges and unsupported constructs are recorded as incompleteness, never ignored.
"""
import ast
import copy
import hashlib
import itertools
import os.path
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path

MAX_VALUES = 16
_IDS = re.compile(r"BenchmarkTest\d+")
_ROUTES = re.compile(r"/benchmark/[A-Za-z]+-\d+/")


def opaque(text: str) -> str:
    """Hide benchmark identity (test IDs, category routes) from anything shown to a model."""
    return _IDS.sub("Handler", _ROUTES.sub("/app/", text))


class _Abstract:
    __slots__ = ("name", "rank")

    def __init__(self, name, rank):
        self.name, self.rank = name, rank

    def __repr__(self):
        return f"<{self.name}>"

    def __deepcopy__(self, memo):
        return self


TRUSTED, UNKNOWN, TAINT = _Abstract("trusted", 1), _Abstract("unknown", 2), _Abstract("tainted", 3)
ABSTRACT = (TRUSTED, UNKNOWN, TAINT)


def worst(vals):
    """The most severe abstract element occurring anywhere in vals (descending into containers)."""
    best = None
    for v in vals:
        for e in _elements(v):
            if isinstance(e, _Abstract) and (best is None or e.rank > best.rank):
                best = e
    return best


def _elements(v):
    if isinstance(v, tuple) and v and v[0] in ("list", "dict", "path"):
        if v[0] == "list":
            for e in v[1]:
                yield from _elements(e)
        elif v[0] == "dict":
            for k, e in v[1]:
                yield from _elements(k)
                yield from _elements(e)
        else:
            yield from _elements(v[1])
    else:
        yield v


def cap(vals: set) -> frozenset:
    vals = frozenset(vals)
    if len(vals) > MAX_VALUES:
        return frozenset({worst(vals) or UNKNOWN}) if worst(vals) else frozenset({UNKNOWN})
    return vals


def show(vals) -> str:
    def one(v):
        if isinstance(v, _Abstract):
            return repr(v)
        if isinstance(v, tuple) and v and v[0] == "list":
            return "[" + ", ".join(one(e) for e in v[1]) + "]"
        if isinstance(v, tuple) and v and v[0] == "dict":
            return "{" + ", ".join(f"{one(k)}: {one(e)}" for k, e in v[1]) + "}"
        if isinstance(v, tuple) and v and v[0] == "path":
            return f"Path({one(v[1])})"
        return repr(v)[:60]
    return " | ".join(sorted(one(v) for v in vals))


# ---------------------------------------------------------------- policy (mirrors baseline rule)

SOURCE_METHODS = {"get_form_parameter", "get_query_parameter", "get_cookie"}
SOURCE_FUNCS = {"helpers.utils.get_parameter", "helpers.utils.get_parameter_list"}
CONSTANT_METHODS = {"get_safe_value": "bar"}          # request_wrapper.get_safe_value returns "bar"
PASSTHROUGH_METHODS = {"doSomething"}                 # ThingFactory things return their argument
SANITIZERS = {"secure_filename", "werkzeug.utils.secure_filename"}
NORMALIZERS = {"os.path.realpath", "os.path.abspath"}  # absolute + normalised (symlinks out of scope)
SAFE_JOIN = {"werkzeug.security.safe_join", "werkzeug.utils.safe_join", "flask.safe_join", "safe_join"}
SINK_FUNCS = {"open", "io.open", "codecs.open", "os.open", "os.path.exists", "os.path.lexists",
              "os.path.isfile", "os.path.isdir", "os.path.getsize", "os.path.getmtime", "os.remove",
              "os.unlink", "os.rmdir", "os.mkdir", "os.makedirs", "os.listdir", "os.scandir", "os.stat",
              "shutil.copy", "shutil.copyfile", "shutil.move", "shutil.rmtree", "flask.send_file",
              "send_file", "flask.send_from_directory", "send_from_directory"}
SINK_METHODS = {"open", "read_text", "read_bytes", "write_text", "write_bytes", "exists", "is_file",
                "is_dir", "stat", "unlink", "rmdir", "mkdir", "touch", "iterdir"}
NORETURN = {"flask.abort", "abort", "werkzeug.exceptions.abort", "sys.exit", "exit", "os._exit"}
UNSUPPORTED_CALLS = {"exec", "eval", "globals", "locals", "vars", "setattr", "getattr", "delattr", "__import__"}


# ---------------------------------------------------------------- records

@dataclass
class Def:
    id: str
    var: str
    line: int
    code: str
    values: frozenset
    depends: list
    in_loop: bool = False
    in_handler: bool = False
    dead: bool = False
    kind: str = "assign"          # assign | mutation | loop_target | with_target | match_capture | augassign
    direct_source: bool = False   # the defining statement reads a source itself


@dataclass
class Var:
    values: frozenset
    defs: frozenset


@dataclass
class Cond:
    id: str                       # statement id of the if/match guard
    code: str
    polarity: bool                # truth value of the condition required to reach the sink
    kind: str                     # enclosing | early_exit | match_case
    reads: dict                   # var -> sorted def ids at the guard
    node: ast.AST = field(repr=False, default=None)


@dataclass
class Snapshot:
    state: dict
    conds: list
    in_loop: bool
    in_handler: bool
    dead: bool


class Unsupported(Exception):
    pass


# ---------------------------------------------------------------- the analysis

class Analyzer:
    def __init__(self, module: ast.Module, func: ast.FunctionDef, sink_stmt: ast.stmt):
        self.module, self.func, self.sink_stmt = module, func, sink_stmt
        self.ids: dict[int, str] = {}
        self.nodes: list[dict] = []
        self.defs: dict[str, Def] = {}
        self.branches: list[dict] = []
        self.flags: set[str] = set()
        self.snapshot: Snapshot | None = None
        self.loop_exits: list[list] = []
        self.raise_points: list[list] = []   # per enclosing try: states from which the body may raise
        self.cur_stmt = None
        self.imports = self._module_imports()
        self.local_funcs = {n.name for n in ast.walk(func) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and n is not func}
        self.module_funcs = {n.name for n in ast.walk(module) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                             and n is not func} - self.local_funcs
        self.mutated_globals = _mutated_nonlocals(module)
        self._number(func.body)

    # --- bookkeeping
    def _module_imports(self) -> dict[str, str]:
        names = {}
        for n in ast.walk(self.module):
            if isinstance(n, ast.Import):
                for a in n.names:
                    names[a.asname or a.name.split(".")[0]] = a.asname and a.name or a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom) and n.module:
                for a in n.names:
                    names[a.asname or a.name] = f"{n.module}.{a.name}"
        return names

    def _number(self, body):
        for s in body:
            sid = f"s{len(self.ids) + 1}"
            self.ids[id(s)] = sid
            self.nodes.append({"id": sid, "line": s.lineno, "kind": type(s).__name__, "code": _header(s)})
            for child in _child_blocks(s):
                if isinstance(child, ast.match_case):
                    cid = f"s{len(self.ids) + 1}"
                    self.ids[id(child)] = cid
                    child.lineno = child.pattern.lineno  # capture definitions are attributed to the case line
                    self.nodes.append({"id": cid, "line": child.pattern.lineno, "kind": "case",
                                       "code": "case " + ast.unparse(child.pattern) + ":"})
                    self._number(child.body)
                else:
                    self._number(child)

    def sid(self, node) -> str:
        return self.ids[id(node)]

    def dotted(self, expr) -> str | None:
        """Qualified name of a Name/Attribute chain, resolving module imports (local names win)."""
        parts = []
        while isinstance(expr, ast.Attribute):
            parts.append(expr.attr)
            expr = expr.value
        if not isinstance(expr, ast.Name):
            return None
        base = self.local_imports.get(expr.id) or self.imports.get(expr.id) or expr.id
        return ".".join([base, *reversed(parts)])

    # --- entry
    def run(self):
        self.local_imports: dict[str, str] = {}
        state: dict[str, Var] = {}
        params = self.func.args
        for a in params.posonlyargs + params.args + params.kwonlyargs + [x for x in (params.vararg, params.kwarg) if x]:
            d = self._def(a.arg, self.func, frozenset({UNKNOWN}), [], kind="parameter", line=self.func.lineno,
                          code=f"parameter {a.arg}", sid="params")
            state[a.arg] = Var(d.values, frozenset({d.id}))
        self.walk(self.func.body, state, [], loop=False, handler=False, dead=False)
        if self.snapshot is None:
            raise Unsupported("sink statement not reached by the walker")

    def _def(self, var, node, values, depends, kind="assign", line=None, code=None, sid=None, ctx=None):
        sid = sid or self.sid(node)
        did = f"{sid}:{var}"
        loop, handler, dead = ctx or (False, False, False)
        d = Def(did, var, line or node.lineno, code or _header(node), values, sorted(set(depends)),
                in_loop=loop, in_handler=handler, dead=dead, kind=kind,
                direct_source=_direct_source(self, node) if isinstance(node, ast.AST) and kind != "parameter" else False)
        self.defs[did] = d
        return d

    # --- statements
    def walk(self, body, state, conds, loop, handler, dead):
        """Walk a block; returns the outgoing state, or None if every path exits."""
        conds = list(conds)
        for s in body:
            if state is None:
                return None
            ctx = (loop, handler, dead)
            if self.raise_points and not dead:  # any statement may raise into an enclosing try
                point = copy.deepcopy(state)
                for col in self.raise_points:
                    col.append(point)
            if s is self.sink_stmt and (self.snapshot is None or loop):  # in loops: keep the fixpoint pass
                self.snapshot = Snapshot(copy.deepcopy(state), list(conds), loop, handler, dead)
            state = self.stmt(s, state, conds, ctx)
        return state

    def stmt(self, s, state, conds, ctx):
        loop, handler, dead = ctx
        self.cur_stmt = s
        if isinstance(s, (ast.Return, ast.Raise)):
            if s is not self.sink_stmt and getattr(s, "value", None) is not None:
                self.ev(s.value, state, ctx)
            return None
        if isinstance(s, (ast.Break, ast.Continue)):
            if self.loop_exits:
                self.loop_exits[-1].append(copy.deepcopy(state))  # leaves the body; rejoins after the loop
            return None
        if isinstance(s, ast.Assign):
            vals, reads = self.ev_reads(s.value, state, ctx)
            if len(s.targets) > 1 and _has_container(vals):
                self.flags.add("unsupported:container_alias")  # a = b = [...]: two names for one object
            for t in s.targets:
                self.assign(t, vals, reads, s, state, ctx)
            return state
        if isinstance(s, ast.AnnAssign):
            if s.value is not None:
                vals, reads = self.ev_reads(s.value, state, ctx)
                self.assign(s.target, vals, reads, s, state, ctx)
            return state
        if isinstance(s, ast.AugAssign):
            expr = ast.BinOp(left=_load(s.target), op=s.op, right=s.value)
            vals, reads = self.ev_reads(expr, state, ctx)
            self.assign(s.target, vals, reads, s, state, ctx, kind="augassign")
            return state
        if isinstance(s, ast.Expr):
            self.ev(s.value, state, ctx, stmt=s)
            if isinstance(s.value, ast.Call) and self.dotted(s.value.func) in NORETURN:
                return None  # abort()/exit() never return
            return state
        if isinstance(s, (ast.Import, ast.ImportFrom)):
            for a in s.names:
                if isinstance(s, ast.Import):
                    self.local_imports[a.asname or a.name.split(".")[0]] = a.asname and a.name or a.name.split(".")[0]
                elif s.module:
                    self.local_imports[a.asname or a.name] = f"{s.module}.{a.name}"
            return state
        if isinstance(s, (ast.Pass, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return state
        if isinstance(s, (ast.Global, ast.Nonlocal, ast.Delete)):
            self.flags.add(f"unsupported:{type(s).__name__}")
            return state
        if isinstance(s, ast.If):
            return self.if_stmt(s, state, conds, ctx)
        if isinstance(s, ast.Match):
            return self.match_stmt(s, state, conds, ctx)
        if isinstance(s, (ast.For, ast.While)):
            return self.loop_stmt(s, state, conds, ctx)
        if isinstance(s, ast.Try):
            return self.try_stmt(s, state, conds, ctx)
        if isinstance(s, ast.With):
            for item in s.items:
                if isinstance(item.context_expr, ast.Call) and \
                        self.dotted(item.context_expr.func) in ("contextlib.suppress", "suppress"):
                    self.flags.add("unsupported:exception_suppressing_with")
                vals, reads = self.ev_reads(item.context_expr, state, ctx)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, frozenset({UNKNOWN}) if worst(vals) is not TAINT else vals,
                                reads, s, state, ctx, kind="with_target")
            return self.walk(s.body, state, conds, loop, handler, dead)
        self.flags.add(f"unsupported:{type(s).__name__}")
        return state

    def assign(self, target, vals, reads, s, state, ctx, kind="assign"):
        rhs = getattr(s, "value", None)
        if isinstance(target, ast.Name) and isinstance(rhs, ast.Name) and rhs.id in state and \
                any(isinstance(v, tuple) and v and v[0] in ("list", "dict") for v in state[rhs.id].values):
            self.flags.add("unsupported:container_alias")  # two names for one mutable object
        if isinstance(target, ast.Name):
            deps = [d for r in reads for d in state.get(r, Var(frozenset(), frozenset())).defs]
            d = self._def(target.id, s, vals, deps, kind=kind, ctx=ctx)
            state[target.id] = Var(vals, frozenset({d.id}))
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.assign(elt, frozenset({worst(vals) or UNKNOWN}) if worst(vals) else frozenset({UNKNOWN}),
                            reads, s, state, ctx, kind)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id in state:
            self._escapes([rhs], state)
            base = target.value.id
            keys = self.ev(target.slice, state, ctx)
            new = set()
            for cur, k, v in itertools.product(state[base].values, keys, vals):
                new.add(_setitem(cur, k, v))
            self._mutate(base, cap(new), reads + [base], s, state, ctx)
        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            self._escapes([rhs], state)
            base = _base_name(target)
            if base and base in state and worst(vals) is TAINT:
                self._mutate(base, cap(set(state[base].values) | {TAINT}), reads + [base], s, state, ctx)
            elif base and base in state:
                self._mutate(base, cap(set(state[base].values) | {UNKNOWN}), reads + [base], s, state, ctx)
        else:
            self.flags.add("unsupported:assign_target")

    def _escapes(self, exprs, state):
        """A local container stored in or passed to something else gets a second, untracked name."""
        if any(isinstance(x, ast.Name) and x.id in state and _has_container(state[x.id].values) for x in exprs):
            self.flags.add("unsupported:container_alias")

    def _mutate(self, var, values, reads, s, state, ctx):
        deps = [d for r in reads for d in state.get(r, Var(frozenset(), frozenset())).defs]
        d = self._def(var, s, values, deps, kind="mutation", ctx=ctx)
        state[var] = Var(values, frozenset({d.id}))

    def _cond(self, node, test, polarity, kind, state):
        reads = {n.id: sorted(state[n.id].defs) for n in ast.walk(test)
                 if isinstance(n, ast.Name) and n.id in state}
        return Cond(self.sid(node), ast.unparse(test), polarity, kind, reads, test)

    def if_stmt(self, s, state, conds, ctx):
        loop, handler, dead = ctx
        truth = _truth(self.ev(s.test, state, ctx))
        feasible = {"both": (True, True), "true": (True, False), "false": (False, True)}[truth]
        self.branches.append({"id": self.sid(s), "line": s.lineno, "condition": ast.unparse(s.test),
                              "feasible_true": feasible[0], "feasible_false": feasible[1]})
        outs = []
        for polarity, block, ok in ((True, s.body, feasible[0]), (False, s.orelse, feasible[1])):
            branch_conds = conds + [self._cond(s, s.test, polarity, "enclosing", state)]
            out = self.walk(block, copy.deepcopy(state), branch_conds, loop, handler, dead or not ok)
            outs.append(out if ok else "pruned")
        live = [o for o in outs if o not in (None, "pruned")]
        if not live:
            return None
        # a guard: exactly one feasible branch continues and the other feasible branch always exits
        if len(live) == 1:
            cont = 0 if outs[0] not in (None, "pruned") else 1
            other = outs[1 - cont]
            if other is None:
                conds.append(self._cond(s, s.test, cont == 0, "early_exit", state))
        return _join(live)

    def match_stmt(self, s, state, conds, ctx):
        loop, handler, dead = ctx
        subject = self.ev(s.subject, state, ctx)
        concrete = worst(subject) is None
        decided, outs = set(), []
        for case in s.cases:
            matched = None
            if concrete and case.guard is None:
                matched = {v for v in subject if v not in decided and _pattern_matches(case.pattern, v) is True}
                undecidable = any(_pattern_matches(case.pattern, v) is None for v in subject if v not in decided)
                ok = bool(matched) or undecidable
                if not undecidable:
                    decided |= matched
            else:
                ok = True
            sub = copy.deepcopy(state)
            top = case.pattern.name if isinstance(case.pattern, ast.MatchAs) else None
            if top:
                self.assign(ast.Name(id=top, ctx=ast.Store()), subject, [], case, sub, ctx, kind="match_capture")
            for name in _captures(case.pattern) - {top}:  # a part of the subject: as severe as its worst element
                self.assign(ast.Name(id=name, ctx=ast.Store()), frozenset({worst(subject) or UNKNOWN}), [], case,
                            sub, ctx, kind="match_capture")
            self.branches.append({"id": self.sid(case), "line": case.pattern.lineno,
                                  "condition": f"match {ast.unparse(s.subject)}: case {ast.unparse(case.pattern)}",
                                  "feasible_true": ok, "feasible_false": None})
            case_conds = conds + [Cond(self.sid(case), f"{ast.unparse(s.subject)} matches {ast.unparse(case.pattern)}",
                                       True, "match_case", {}, None)]
            out = self.walk(case.body, sub, case_conds, loop, handler, dead or not ok)
            if ok and out is not None:
                outs.append(out)
        fallthrough = not (concrete and decided == set(subject)) and not any(
            isinstance(c.pattern, ast.MatchAs) and c.pattern.pattern is None and c.guard is None for c in s.cases)
        if fallthrough:
            outs.append(state)
        return _join(outs) if outs else None

    def loop_stmt(self, s, state, conds, ctx, max_rounds=5):
        """Iterate the body to a fixpoint; values that do not stabilise are widened and flagged."""
        loop, handler, dead = ctx
        before = copy.deepcopy(state)
        head, exits_all, out = copy.deepcopy(state), [], None
        converged = False
        for _ in range(max_rounds):
            inner = copy.deepcopy(head)
            if isinstance(s, ast.For):
                vals, reads = self.ev_reads(s.iter, inner, (True, handler, dead))
                elem = frozenset({worst(vals)}) if worst(vals) in (TAINT, UNKNOWN) else _iter_elems(vals)
                if _has_container(elem):
                    self.flags.add("unsupported:container_alias")  # the loop variable names a nested container
                self.assign(s.target, elem, reads, s, inner, (True, handler, dead), kind="loop_target")
            else:
                self.ev(s.test, inner, ctx)
            self.loop_exits.append([])
            out = self.walk(s.body, inner, conds, True, handler, dead)
            exits_all = self.loop_exits.pop()
            new_head = _join([head] + ([out] if out is not None else []) + exits_all)
            if _same_values(new_head, head):
                converged = True
                break
            head = new_head
        else:
            self.flags.add("unsupported:loop_not_converged")
            head = {v: Var(frozenset({worst(x.values) or UNKNOWN}) if not _same_var(x, before.get(v)) else x.values,
                           x.defs) for v, x in head.items()}
        after = _join([before, head] + ([out] if out is not None else []) + exits_all)
        if s.orelse:
            # `else` runs only when the loop ends without break; break and continue exits are not told apart,
            # so every jump state also bypasses it (an over-approximation)
            bypass = [copy.deepcopy(x) for x in exits_all] + ([] if converged else [copy.deepcopy(head)])
            normal = self.walk(s.orelse, after, conds, loop, handler, dead)
            after = _join([normal] + bypass)
        return after

    def try_stmt(self, s, state, conds, ctx):
        """Any statement in the body may raise, so handlers start from every state reached inside it, nested
        blocks included. A finally block containing the sink also sees abrupt completions (return, raise)."""
        loop, handler, dead = ctx
        if s.finalbody and _jumps_out(s.body + [x for h in s.handlers for x in h.body] + s.orelse):
            self.flags.add("unsupported:jump_through_finally")
        self.raise_points.append([copy.deepcopy(state)])
        body_out = self.walk(s.body, state, conds, loop, handler, dead)
        body_points = self.raise_points.pop()
        if body_out is not None:  # also the completed body (an over-approximation kept from the frozen analysis)
            body_points.append(copy.deepcopy(body_out))
        self.raise_points.append([])
        outs = []
        if body_out is not None:
            out = self.walk(s.orelse, body_out, conds, loop, handler, dead) if s.orelse else body_out
            if out is not None:
                outs.append(out)
        entry = _join(body_points)
        for h in s.handlers:
            hstate = copy.deepcopy(entry)
            if h.name:
                hstate[h.name] = Var(frozenset({UNKNOWN}), frozenset())
            out = self.walk(h.body, hstate, conds, loop, True, dead)
            if out is not None:
                outs.append(out)
        other_points = self.raise_points.pop()
        after = _join(outs) if outs else None
        if s.finalbody:
            abrupt = _join(body_points + other_points)
            if self.raise_points or _contains(s.finalbody, self.sink_stmt):
                base = _join([after, abrupt])  # over-approximates the state after the try as well
            else:
                base = copy.deepcopy(after) if after is not None else abrupt
            after_f = self.walk(s.finalbody, base, conds, loop, handler, dead)
            if after_f is not None:
                for col in self.raise_points:  # a pending exception re-raises after finally
                    col.append(copy.deepcopy(after_f))
            after = after_f if after is not None else None
        return after

    # --- expressions
    def ev_reads(self, expr, state, ctx):
        reads = sorted({n.id for n in ast.walk(expr) if isinstance(n, ast.Name) and n.id in state})
        return self.ev(expr, state, ctx), reads

    def ev(self, e, state, ctx, stmt=None) -> frozenset:
        try:
            return cap(self._ev(e, state, ctx, stmt))
        except RecursionError:
            return frozenset({UNKNOWN})

    def _ev(self, e, state, ctx, stmt):
        ev = lambda x: self.ev(x, state, ctx, stmt)
        if isinstance(e, ast.Constant):
            return {e.value}
        if isinstance(e, ast.Name):
            if e.id in state:
                return set(state[e.id].values)
            q = self.dotted(e)
            if q == "flask.request":
                return {TAINT}
            if e.id in self.mutated_globals or e.id in self.local_funcs or e.id in self.module_funcs:
                return {UNKNOWN}  # mutated by some function, or a function whose result is not modelled
            return {TRUSTED}  # module-level constant or module object
        if isinstance(e, ast.Attribute):
            q = self.dotted(e)
            if q and (q == "flask.request" or q.startswith("flask.request.")):
                return {TAINT}
            base = ev(e.value)
            w = worst(base)
            if w is TAINT:
                return {TAINT}
            if isinstance(e.value, ast.Name) and e.value.id not in state:
                if e.value.id in self.mutated_globals:
                    return {UNKNOWN}
                return {TRUSTED}  # module attribute, e.g. helpers.utils.TESTFILES_DIR or os.sep
            if q == "os.sep" or e.attr == "sep":
                return {"/"}
            return {UNKNOWN} if w is UNKNOWN or w is None else {w}
        if isinstance(e, ast.JoinedStr):
            parts = [ev(v.value) if isinstance(v, ast.FormattedValue) else {v.value} for v in e.values]
            return _lift(lambda *xs: "".join(str(x) for x in xs), parts)
        if isinstance(e, ast.BinOp):
            return _lift(lambda a, b: _binop(e.op, a, b), [ev(e.left), ev(e.right)])
        if isinstance(e, ast.UnaryOp):
            return _lift(lambda a: _unary(e.op, a), [ev(e.operand)])
        if isinstance(e, ast.BoolOp):
            vals = [ev(v) for v in e.values]
            return _lift(lambda *xs: _boolop(e.op, xs), vals)
        if isinstance(e, ast.Compare):
            vals = [ev(e.left)] + [ev(c) for c in e.comparators]
            return _lift(lambda *xs: _compare(e.ops, xs), vals)
        if isinstance(e, ast.IfExp):
            t = _truth(ev(e.test))
            return (ev(e.body) if t != "false" else set()) | (ev(e.orelse) if t != "true" else set())
        if isinstance(e, (ast.List, ast.Tuple)):
            self._escapes(e.elts, state)
            elems = [ev(x) for x in e.elts]
            return {("list", tuple(c)) for c in itertools.product(*elems)} if _small(elems) else {_join_worst(elems)}
        if isinstance(e, ast.Dict):
            if any(k is None for k in e.keys):
                return {UNKNOWN}
            self._escapes(e.values, state)
            ks, vs = [ev(k) for k in e.keys], [ev(v) for v in e.values]
            if not _small(ks + vs):
                return {_join_worst(ks + vs)}
            out = set()
            for kc in itertools.product(*ks):
                for vc in itertools.product(*vs):
                    out.add(("dict", tuple(zip(kc, vc))))
            return out
        if isinstance(e, ast.Subscript):
            base, key = ev(e.value), ev(e.slice)
            return _lift(_getitem, [base, key])
        if isinstance(e, ast.Slice):
            parts = [ev(x) if x is not None else {None} for x in (e.lower, e.upper, e.step)]
            return _lift(lambda a, b, c: ("slice", a, b, c), parts)
        if isinstance(e, ast.Call):
            return self.call(e, state, ctx, stmt)
        if isinstance(e, (ast.ListComp, ast.GeneratorExp, ast.SetComp, ast.DictComp, ast.Lambda,
                          ast.NamedExpr, ast.Await, ast.Yield, ast.YieldFrom, ast.Set, ast.Starred)):
            self.flags.add(f"unsupported:{type(e).__name__}")
            inner = [ev(n) for n in ast.iter_child_nodes(e) if isinstance(n, ast.expr)]
            return {TAINT} if any(worst(v) is TAINT for v in inner) else {UNKNOWN}
        return {UNKNOWN}

    def call(self, e, state, ctx, stmt):
        ev = lambda x: self.ev(x, state, ctx, stmt)
        args = [ev(a) for a in e.args]
        kwargs = [ev(k.value) for k in e.keywords]
        everything = args + kwargs
        q = self.dotted(e.func)
        if q in UNSUPPORTED_CALLS:
            self.flags.add(f"unsupported:{q}")
            return {TAINT} if _join_worst(everything) is TAINT else {UNKNOWN}
        if isinstance(e.func, ast.Name) and (e.func.id in state or e.func.id in self.local_funcs
                                             or e.func.id in self.module_funcs):
            # a function defined in this module, or held in a variable: its body is not analysed
            if e.func.id in self.local_funcs:
                self.flags.add("unsupported:local_function_call")  # may rebind or mutate captured locals
            self._escapes(e.args + [k.value for k in e.keywords], state)
            self._taint_arguments(e, everything, state, ctx)
            return {TAINT} if _join_worst(everything) is TAINT else {UNKNOWN}
        if q in SANITIZERS:
            return {TRUSTED}
        if q in SOURCE_FUNCS:
            return {TAINT}
        if q in _PURE:
            return _lift(_PURE[q], args) if not e.keywords else {_join_worst(everything) or TRUSTED}
        if isinstance(e.func, ast.Attribute):
            meth, recv_node = e.func.attr, e.func.value
            if meth in SOURCE_METHODS:
                return {TAINT}
            if meth in CONSTANT_METHODS:
                return {CONSTANT_METHODS[meth]}
            if meth in PASSTHROUGH_METHODS and args:
                return set(args[0]) | {""}
            if isinstance(recv_node, ast.Name) and recv_node.id in state:
                return self.method_on_local(e, recv_node.id, meth, args, state, ctx)
            recv = ev(recv_node)
            if not all(isinstance(r, str) for r in recv) and meth not in _PURE_METHODS:
                self._escapes(e.args + [k.value for k in e.keywords], state)
                self._taint_arguments(e, everything, state, ctx)
            return _method_on_value(meth, recv, args, everything)
        # library function: propagates its inputs (as Semgrep's default does)
        if q not in _NON_RETAINING:
            self._escapes(e.args + [k.value for k in e.keywords], state)
            self._taint_arguments(e, everything, state, ctx)
        w = _join_worst(everything)
        return {w} if w in (TAINT, UNKNOWN) else {TRUSTED}

    def _taint_arguments(self, e, everything, state, ctx):
        """An unmodelled call given attacker data may store it in any mutable local it is also given."""
        if _join_worst(everything) is not TAINT:
            return
        for a in e.args + [k.value for k in e.keywords]:
            if isinstance(a, ast.Name) and a.id in state and worst(state[a.id].values) is not TAINT and \
                    not all(isinstance(v, (str, bytes, int, float, bool, type(None))) for v in state[a.id].values):
                self._mutate(a.id, cap(set(state[a.id].values) | {TAINT}), [a.id], self.cur_stmt, state, ctx)

    def method_on_local(self, e, var, meth, args, state, ctx):
        recv = state[var].values
        reads = [var] + [n.id for a in e.args for n in ast.walk(a) if isinstance(n, ast.Name) and n.id in state]
        if _has_container(recv) or meth not in _PURE_METHODS:
            self._escapes(e.args + [k.value for k in e.keywords], state)  # e.g. outer.append(inner)
        if meth in _LIST_MUTATORS and any(isinstance(r, tuple) and r and r[0] in ("list", "dict") for r in recv):
            new, results = set(), set()
            for r in recv:
                for combo in (itertools.product(*args) if args else [()]):
                    out = _list_mutate(r, meth, combo)
                    if out is None:
                        bad = TAINT if worst({r, *combo}) is TAINT else UNKNOWN
                        new.add(bad)
                        results.add(bad)
                    else:
                        new.add(out[0])
                        results.add(out[1])
            self._mutate(var, cap(new), reads, self.cur_stmt, state, ctx)
            return results
        result = _method_on_value(meth, recv, args, args)
        # unmodelled method with a tainted argument taints its receiver (side effect, e.g. ConfigParser.set)
        if _join_worst(args) is TAINT and worst(recv) is not TAINT and meth not in _PURE_METHODS:
            self._mutate(var, cap(set(recv) | {TAINT}), reads, self.cur_stmt, state, ctx)
        return result


# ---------------------------------------------------------------- value helpers

def _has_container(vals) -> bool:
    return any(isinstance(v, tuple) and v and v[0] in ("list", "dict") for v in vals)


def _captures(pattern) -> set:
    names = set()
    for n in ast.walk(pattern):
        if isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            names.add(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            names.add(n.rest)
    return names


def _contains(body, target) -> bool:
    return target is not None and any(n is target for s in body for n in ast.walk(s))


def _jumps_out(body) -> bool:
    """A break or continue in body that leaves it (not one belonging to a loop nested inside it)."""
    for s in body:
        if isinstance(s, (ast.Break, ast.Continue)):
            return True
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(s, (ast.For, ast.While)):
            if _jumps_out(s.orelse):
                return True
            continue
        if any(_jumps_out(b) for b in _child_blocks(s) if isinstance(b, list)) or \
                (isinstance(s, ast.Match) and any(_jumps_out(c.body) for c in s.cases)):
            return True
    return False


_MUTATOR_METHODS = {"append", "extend", "insert", "update", "setdefault", "pop", "popitem", "remove", "clear",
                    "add", "discard", "set", "read", "read_string", "read_dict", "read_file", "__setitem__"}


def _mutated_nonlocals(module) -> set:
    """Names some function in the module rebinds (global) or mutates without binding them locally.

    Their module-level value is not a trustworthy constant: any handler may have stored request data in them.
    """
    out = set()
    for f in (n for n in ast.walk(module) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        params = f.args
        local = {a.arg for a in params.posonlyargs + params.args + params.kwonlyargs} | \
                {a.arg for a in (params.vararg, params.kwarg) if a} | \
                {n.id for n in ast.walk(f) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        for n in ast.walk(f):
            if isinstance(n, ast.Global):
                out |= set(n.names)
            elif isinstance(n, (ast.Subscript, ast.Attribute)) and isinstance(n.ctx, (ast.Store, ast.Del)):
                b = _base_name(n)
                if b and b not in local:
                    out.add(b)
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _MUTATOR_METHODS:
                b = _base_name(n.func.value)
                if b and b not in local:
                    out.add(b)
    return out


def _load(target):
    t = copy.deepcopy(target)
    for n in ast.walk(t):
        if hasattr(n, "ctx"):
            n.ctx = ast.Load()
    return t


def _base_name(node):
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _small(sets) -> bool:
    total = 1
    for s in sets:
        total *= max(len(s), 1)
    return total <= MAX_VALUES


def _join_worst(sets):
    return worst(set().union(*sets)) if sets else None


def _lift(fn, arg_sets):
    """Apply fn to every combination of concrete arguments; abstract inputs propagate by severity."""
    out = set()
    if not _small(arg_sets):
        return {_join_worst(arg_sets) or UNKNOWN}
    for combo in itertools.product(*arg_sets):
        w = worst(set(combo))
        if w is not None and not all(_container_ok(c) for c in combo):
            out.add(w)
            continue
        try:
            out.add(fn(*combo))
        except _NeedsAbstract as x:
            out.add(x.value)
        except Exception:
            out.add(w or UNKNOWN)
    return out


class _NeedsAbstract(Exception):
    def __init__(self, value):
        self.value = value


def _container_ok(v):
    """Abstract elements may sit inside containers; operations on containers handle them per element."""
    return not isinstance(v, _Abstract)


def _plain(v):
    if isinstance(v, _Abstract):
        raise _NeedsAbstract(v)
    if isinstance(v, tuple) and v and v[0] == "list":
        return [_plain(x) for x in v[1]]
    if isinstance(v, tuple) and v and v[0] == "path":
        return Path(_plain(v[1]))
    if isinstance(v, tuple) and v and v[0] == "dict":
        return {_plain(k): _plain(x) for k, x in v[1]}
    return v


def _binop(op, a, b):
    if isinstance(op, ast.Div) and isinstance(a, tuple) and a and a[0] == "path":
        w = worst({b})
        if w is not None:
            raise _NeedsAbstract(w)
        return ("path", posixpath.join(_plain(a[1]), str(_plain(b))))
    x, y = _plain(a), _plain(b)
    return {ast.Add: lambda: x + y, ast.Mod: lambda: x % y, ast.Mult: lambda: x * y,
            ast.Sub: lambda: x - y}[type(op)]()


def _unary(op, a):
    x = _plain(a)
    return {ast.Not: lambda: not x, ast.USub: lambda: -x, ast.UAdd: lambda: +x}[type(op)]()


def _boolop(op, xs):
    vals = [_plain(x) for x in xs]
    return all(vals) if isinstance(op, ast.And) else any(vals)


def _compare(ops, xs):
    vals = [_plain(x) for x in xs]
    fns = {ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b, ast.In: lambda a, b: a in b,
           ast.NotIn: lambda a, b: a not in b, ast.Is: lambda a, b: a is b, ast.IsNot: lambda a, b: a is not b,
           ast.Lt: lambda a, b: a < b, ast.Gt: lambda a, b: a > b, ast.LtE: lambda a, b: a <= b,
           ast.GtE: lambda a, b: a >= b}
    return all(fns[type(o)](vals[i], vals[i + 1]) for i, o in enumerate(ops))


def _truth(vals) -> str:
    seen = set()
    for v in vals:
        if worst({v}) is not None and not (isinstance(v, tuple) and v[0] == "list"):
            return "both"
        try:
            seen.add(bool(_plain(v)))
        except _NeedsAbstract:
            return "both"
        except Exception:
            return "both"
    if seen == {True}:
        return "true"
    if seen == {False}:
        return "false"
    return "both"


def _getitem(base, key):
    if isinstance(key, tuple) and key and key[0] == "slice":
        _, lo, hi, st = key
        if isinstance(base, tuple) and base and base[0] == "list":
            return ("list", base[1][slice(_plain(lo), _plain(hi), _plain(st))])
        return _plain(base)[slice(_plain(lo), _plain(hi), _plain(st))]
    if isinstance(base, tuple) and base and base[0] == "list":
        return base[1][_plain(key)]
    if isinstance(base, tuple) and base and base[0] == "dict":
        k = _plain(key)
        for kk, vv in base[1]:
            if worst({kk}) is not None:
                raise _NeedsAbstract(UNKNOWN)
            if _plain(kk) == k:
                return vv
        raise KeyError(k)
    return _plain(base)[_plain(key)]


def _setitem(cur, key, val):
    if isinstance(cur, tuple) and cur and cur[0] == "dict" and worst({key}) is None:
        items = [(k, v) for k, v in cur[1] if worst({k}) is not None or _plain(k) != _plain(key)]
        return ("dict", tuple(items + [(key, val)]))
    if isinstance(cur, tuple) and cur and cur[0] == "list" and worst({key}) is None:
        lst = list(cur[1])
        lst[_plain(key)] = val
        return ("list", tuple(lst))
    return TAINT if worst({cur, key, val}) is TAINT else UNKNOWN


_LIST_MUTATORS = {"append", "pop", "insert", "extend", "remove", "reverse", "clear"}


def _list_mutate(r, meth, args):
    if not (isinstance(r, tuple) and r and r[0] == "list"):
        if isinstance(r, tuple) and r and r[0] == "dict" and meth == "pop" and args and worst({args[0]}) is None:
            items = [(k, v) for k, v in r[1] if worst({k}) is None and _plain(k) != _plain(args[0])]
            hit = [v for k, v in r[1] if worst({k}) is None and _plain(k) == _plain(args[0])]
            return (("dict", tuple(items)), hit[0] if hit else (args[1] if len(args) > 1 else UNKNOWN))
        return None
    lst = list(r[1])
    try:
        if meth == "append":
            lst.append(args[0]); res = None
        elif meth == "pop":
            res = lst.pop(_plain(args[0])) if args else lst.pop()
        elif meth == "insert":
            lst.insert(_plain(args[0]), args[1]); res = None
        elif meth == "extend":
            ext = args[0]
            if not (isinstance(ext, tuple) and ext and ext[0] == "list"):
                return None
            lst.extend(ext[1]); res = None
        elif meth == "remove":
            if worst({args[0]}) is not None or any(worst({x}) is not None for x in lst):
                return None
            lst.remove(_plain(args[0])); res = None
        elif meth == "reverse":
            lst.reverse(); res = None
        else:
            lst.clear(); res = None
    except (IndexError, ValueError, _NeedsAbstract, TypeError):
        return None
    return ("list", tuple(lst)), res


def _iter_elems(vals):
    out = set()
    for v in vals:
        if isinstance(v, tuple) and v and v[0] == "list":
            out |= set(v[1])
        else:
            out.add(UNKNOWN)
    return cap(out) or frozenset({UNKNOWN})


_PURE_METHODS = {"lower", "upper", "strip", "lstrip", "rstrip", "replace", "split", "join", "format",
                 "encode", "decode", "startswith", "endswith", "find", "rfind", "index", "count",
                 "get", "keys", "values", "items", "copy", "title", "casefold", "splitlines", "partition",
                 "resolve", "absolute", "as_posix", "is_relative_to", "relative_to", "joinpath", "with_name"}


def _method_on_value(meth, recv, args, everything):
    w_args = _join_worst(everything) if everything else None
    out = set()
    for r in recv:
        if isinstance(r, _Abstract):
            out.add(TAINT if TAINT in (r, w_args) else (UNKNOWN if r is UNKNOWN or w_args is UNKNOWN else TRUSTED))
            continue
        if isinstance(r, tuple) and r and r[0] == "path":
            res = _path_method(r, meth, args)
            out |= res
            continue
        if isinstance(r, tuple) and r and r[0] == "dict" and meth == "get" and args:
            for k in args[0]:
                if worst({k}) is not None:  # unknown key: any stored value, or the default
                    out |= {v for _, v in r[1]} | (set(args[1]) if len(args) > 1 else {None})
                    continue
                hit = [v for kk, v in r[1] if worst({kk}) is None and _plain(kk) == _plain(k)]
                out |= {hit[0]} if hit else (set(args[1]) if len(args) > 1 else {None})
            continue
        if meth in _PURE_METHODS:
            out |= _lift(lambda x, *a: getattr(_plain(x), meth)(*[_plain(y) for y in a]), [{r}, *args])
        else:
            out.add(TAINT if w_args is TAINT else UNKNOWN)
    return out


def _path_method(r, meth, args):
    inner = r[1]
    if worst({inner}) is not None:
        return {worst({inner})}
    p = _plain(inner)
    if meth == "resolve":
        return {TRUSTED}
    if meth in ("as_posix", "__str__"):
        return {p}
    if meth == "joinpath":
        return _lift(lambda *a: ("path", posixpath.join(p, *[str(_plain(x)) for x in a])), args)
    return {UNKNOWN}


def _str(x):
    if isinstance(x, tuple) and x and x[0] == "path":
        return _plain(x[1])
    return str(_plain(x))


def _path_ctor(*xs):
    if not xs:
        return ("path", ".")
    parts = [str(_plain(x[1]) if isinstance(x, tuple) and x and x[0] == "path" else _plain(x)) for x in xs]
    return ("path", posixpath.normpath(posixpath.join(*parts)) if parts[0] != "" else ".")


def _abs_norm(_):
    raise _NeedsAbstract(TRUSTED)  # depends on the working directory / filesystem; untainted if input is


_PURE = {
    "os.path.join": lambda *xs: posixpath.join(*[_plain(x) for x in xs]),
    "os.path.normpath": lambda x: posixpath.normpath(_plain(x)),
    "os.path.basename": lambda x: posixpath.basename(_plain(x)),
    "os.path.dirname": lambda x: posixpath.dirname(_plain(x)),
    "os.path.realpath": _abs_norm, "os.path.abspath": _abs_norm,
    "str": _str, "len": lambda x: len(_plain(x)), "int": lambda x: int(_plain(x)),
    "urllib.parse.unquote_plus": lambda x: __import__("urllib.parse").parse.unquote_plus(_plain(x)),
    "urllib.parse.unquote": lambda x: __import__("urllib.parse").parse.unquote(_plain(x)),
    "pathlib.Path": _path_ctor, "pathlib.PurePath": _path_ctor, "Path": _path_ctor,
}

# library functions known not to keep a reference to (or mutate) a container argument
_NON_RETAINING = set(_PURE) | SANITIZERS | NORMALIZERS | SINK_FUNCS | {"len", "repr", "list", "tuple", "sorted",
                                                                     "print", "bool", "float"}


def _join(states):
    states = [s for s in states if s is not None]
    if not states:
        return None
    out = {}
    for var in set().union(*[s.keys() for s in states]):
        present = [s[var] for s in states if var in s]
        vals = set().union(*[p.values for p in present])
        if len(present) < len(states):
            vals |= {UNKNOWN}  # possibly undefined on some path
        out[var] = Var(cap(vals), frozenset().union(*[p.defs for p in present]))
    return out


def _same_values(a, b) -> bool:
    if a is None or b is None:
        return a is b
    return a.keys() == b.keys() and all(a[k].values == b[k].values and a[k].defs == b[k].defs for k in a)


def _same_var(x, y) -> bool:
    return y is not None and x.values == y.values


def _pattern_matches(p, v):
    """True / False / None (undecidable) for simple match patterns against a concrete value."""
    if isinstance(p, ast.MatchValue) and isinstance(p.value, ast.Constant):
        return v == p.value.value
    if isinstance(p, ast.MatchSingleton):
        return v is p.value
    if isinstance(p, ast.MatchOr):
        res = [_pattern_matches(q, v) for q in p.patterns]
        return True if True in res else (None if None in res else False)
    if isinstance(p, ast.MatchAs) and p.pattern is None:
        return True
    return None


def _child_blocks(s):
    if isinstance(s, (ast.If, ast.For, ast.While)):
        return [s.body, s.orelse]
    if isinstance(s, ast.With):
        return [s.body]
    if isinstance(s, ast.Try):
        return [s.body] + [h.body for h in s.handlers] + [s.orelse, s.finalbody]
    if isinstance(s, ast.Match):
        return list(s.cases)
    return []


def _header(s) -> str:
    if isinstance(s, ast.If):
        return f"if {ast.unparse(s.test)}:"
    if isinstance(s, ast.For):
        return f"for {ast.unparse(s.target)} in {ast.unparse(s.iter)}:"
    if isinstance(s, ast.While):
        return f"while {ast.unparse(s.test)}:"
    if isinstance(s, ast.With):
        return "with " + ", ".join(ast.unparse(i) for i in s.items) + ":"
    if isinstance(s, ast.Try):
        return "try:"
    if isinstance(s, ast.Match):
        return f"match {ast.unparse(s.subject)}:"
    if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return f"def {s.name}(...):"
    if isinstance(s, ast.ExceptHandler):
        return "except:"
    return ast.unparse(s)


# ---------------------------------------------------------------- locating the alert

def _innermost_function(tree, line):
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno <= line <= n.end_lineno:
            if best is None or n.lineno >= best.lineno:
                best = n
    return best


def _locate(func, numbered: dict, line, col, end_line, end_col):
    """The alerted expression, its sink call, and the innermost numbered statement containing the call."""
    target = None
    for n in ast.walk(func):
        if isinstance(n, ast.expr) and (n.lineno, n.col_offset + 1, n.end_lineno, n.end_col_offset + 1) == \
                (line, col, end_line, end_col):
            target = n
            break
    if target is None:
        raise Unsupported("alert span does not match an expression")
    parent = {id(c): p for p in ast.walk(func) for c in ast.iter_child_nodes(p)}
    call = parent.get(id(target))
    if isinstance(call, ast.Attribute) and call.value is target:
        call = parent.get(id(call))
    if not isinstance(call, ast.Call):
        raise Unsupported("alerted expression is not a sink argument or receiver")
    stmt = call
    while not (isinstance(stmt, ast.stmt) and id(stmt) in numbered):
        stmt = parent.get(id(stmt))
        if stmt is None or stmt is func:
            raise Unsupported("sink is not inside a numbered statement of the function")
    return target, call, stmt


# ---------------------------------------------------------------- facts and recognizers

def _sink_name(an: Analyzer, call: ast.Call, target) -> str:
    if isinstance(call.func, ast.Attribute) and call.func.value is target:
        return f"<path>.{call.func.attr}()"
    return an.dotted(call.func) or ast.unparse(call.func)


def _value_kind(vals) -> str:
    w = worst(vals)
    return {None: "constant", TRUSTED: "trusted", UNKNOWN: "unknown", TAINT: "tainted"}[w]


def _containment(an: Analyzer, snap: Snapshot, target) -> list[dict]:
    """Sound containment guards on the sink value (recognizer D4); empty if none apply."""
    var = _guarded_var(target)
    if var is None or var not in snap.state:
        return []
    defs = sorted(snap.state[var].defs)
    if len(defs) != 1:
        return []
    d = an.defs[defs[0]]
    rhs = _def_rhs(an, d)
    if rhs is None or not _is_normalized(an, rhs):
        return []
    out = []
    for c in snap.conds:
        if c.node is None or c.reads.get(var) != defs:
            continue
        for atom, required in _atoms(c.node, c.polarity):
            kind = required and _is_containment_atom(an, snap, c, atom, var)
            if kind:
                out.append({"guard": c.id, "condition": c.code, "recognizer": kind})
    return out


def _guarded_var(e):
    if isinstance(e, ast.Name):
        return e.id
    if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == "str" and len(e.args) == 1 \
            and isinstance(e.args[0], ast.Name):
        return e.args[0].id
    return None


def _def_rhs(an, d: Def):
    for n in ast.walk(an.func):
        if isinstance(n, (ast.Assign, ast.AnnAssign)) and an.ids.get(id(n)) == d.id.split(":")[0]:
            return n.value
    return None


def _is_normalized(an, rhs) -> bool:
    if isinstance(rhs, ast.Call):
        q = an.dotted(rhs.func)
        if q in NORMALIZERS:
            return True
        if isinstance(rhs.func, ast.Attribute) and rhs.func.attr == "resolve":
            return True
    return False


def _atoms(test, polarity):
    """Atomic predicates with the truth value each must have for the guard to hold with `polarity`."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        yield from _atoms(test.operand, not polarity)
    elif isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And) and polarity:
        for v in test.values:
            yield from _atoms(v, True)
    elif isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or) and not polarity:
        for v in test.values:
            yield from _atoms(v, False)
    elif isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.NotEq):
        yield ast.Compare(left=test.left, ops=[ast.Eq()], comparators=test.comparators), not polarity
    else:
        yield test, polarity


def _is_containment_atom(an, snap, cond, atom, var) -> str | None:
    """The atom confines the normalised var under a trusted root: v.startswith(root + sep),
    v.is_relative_to(root) or commonpath([root, v]) == root (the root, not v, on the right)."""
    def is_var(x):
        return _guarded_var(x) == var

    if isinstance(atom, ast.Call) and isinstance(atom.func, ast.Attribute):
        if atom.func.attr == "startswith" and is_var(atom.func.value) and len(atom.args) == 1:
            root = _root_of_prefix(an, atom.args[0])
            if root is not None and _trusted_root(an, snap, cond, root, var):
                return "startswith(root + sep)"
        if atom.func.attr == "is_relative_to" and is_var(atom.func.value) and len(atom.args) == 1:
            if _trusted_root(an, snap, cond, atom.args[0], var):
                return "is_relative_to(root)"
    if isinstance(atom, ast.Compare) and len(atom.ops) == 1 and isinstance(atom.ops[0], ast.Eq):
        sides = [atom.left, atom.comparators[0]]
        for a, b in (sides, sides[::-1]):
            if isinstance(a, ast.Call) and an.dotted(a.func) == "os.path.commonpath" and len(a.args) == 1 \
                    and isinstance(a.args[0], (ast.List, ast.Tuple)) and len(a.args[0].elts) == 2:
                elts = a.args[0].elts
                roots = [x for x in elts if not is_var(x)]
                if len(roots) == 1 and any(is_var(x) for x in elts) and not is_var(b) \
                        and ast.dump(roots[0]) == ast.dump(b) and _trusted_root(an, snap, cond, b, var):
                    return "commonpath([root, v]) == root"
    return None


def _root_of_prefix(an, e):
    """root for a prefix of the form root + '/', root + os.sep, os.path.join(root, '') or '/abs/dir/'."""
    if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
        r = e.right
        if (isinstance(r, ast.Constant) and r.value == "/") or an.dotted(r) == "os.sep":
            return e.left
    if isinstance(e, ast.Call) and an.dotted(e.func) == "os.path.join" and len(e.args) == 2 \
            and isinstance(e.args[1], ast.Constant) and e.args[1].value == "":
        return e.args[0]
    if isinstance(e, ast.Constant) and isinstance(e.value, str) and e.value.endswith("/") and len(e.value) > 1:
        return ast.Constant(e.value.rstrip("/"))
    return None


_ROOT_FUNCS = {"os.path.join", "os.path.abspath", "os.path.realpath", "os.path.normpath", "str", "pathlib.Path",
               "pathlib.PurePath", "Path"}


def _trusted_root(an, snap, cond, e, var) -> bool:
    """The root is untainted configuration: built only from constants, module constants and locals whose
    untainted definitions reach both the guard and the sink, and (when concrete) an absolute non-/ path."""
    for n in ast.walk(e):
        if isinstance(n, ast.Name):
            if n.id == var or (n.id in snap.state and sorted(snap.state[n.id].defs) != cond.reads.get(n.id)):
                return False
        elif isinstance(n, ast.Call):
            if an.dotted(n.func) not in _ROOT_FUNCS and not (isinstance(n.func, ast.Attribute)
                                                            and n.func.attr == "resolve" and not n.args):
                return False
        elif isinstance(n, ast.BinOp):
            if not isinstance(n.op, (ast.Add, ast.Div)):
                return False
        elif not isinstance(n, (ast.Constant, ast.Attribute, ast.JoinedStr, ast.FormattedValue, ast.expr_context,
                                ast.operator, ast.keyword)):
            return False
    vals = an.ev(e, copy.deepcopy(snap.state), (snap.in_loop, snap.in_handler, snap.dead))
    if worst(vals) not in (None, TRUSTED):
        return False
    for v in vals:
        if worst({v}) is None:
            p = v[1] if isinstance(v, tuple) and v and v[0] == "path" else v
            if not isinstance(p, str) or not p.startswith("/") or posixpath.normpath(p) == "/":
                return False
    return True


def _direct_source(an, target) -> bool:
    """The sink expression reads a source directly (not through a local definition)."""
    for n in ast.walk(target):
        q = an.dotted(n) if isinstance(n, (ast.Attribute, ast.Name)) else None
        if q and (q == "flask.request" or q.startswith("flask.request.")):
            return True
        if isinstance(n, ast.Call):
            if an.dotted(n.func) in SOURCE_FUNCS or (isinstance(n.func, ast.Attribute) and n.func.attr in SOURCE_METHODS):
                return True
    return False


def _uncovered_tainted(an, start_defs, cut) -> set:
    """Taint origins reachable backwards from the sink without crossing the guarded (cut) definitions.

    An origin is a tainted definition that reads a source directly, or whose taint has no tainted
    local dependency (e.g. a loop over request headers). Empty result = the guard covers every flow.
    """
    seen, out, frontier = set(), set(), [d for d in start_defs if d not in cut]
    while frontier:
        d = frontier.pop()
        if d in seen or d not in an.defs:
            continue
        seen.add(d)
        dd = an.defs[d]
        tainted_deps = [x for x in dd.depends if x in an.defs and worst(an.defs[x].values) is TAINT]
        if worst(dd.values) is TAINT and (dd.direct_source or not tainted_deps):
            out.add(d)
        frontier.extend(x for x in dd.depends if x not in cut)
    return out


def _transformations(an, snap, target, depth=6) -> list[str]:
    chain, expr, seen = [], target, set()
    for _ in range(depth):
        calls = [an.dotted(n.func) or ast.unparse(n.func) for n in ast.walk(expr) if isinstance(n, ast.Call)]
        chain.extend(c for c in calls if c not in chain)
        var = _guarded_var(expr) if not isinstance(expr, ast.Name) else expr.id
        if var is None or var not in snap.state or len(snap.state[var].defs) != 1:
            break
        did = next(iter(snap.state[var].defs))
        if did in seen:
            break
        seen.add(did)
        rhs = _def_rhs(an, an.defs[did])
        if rhs is None:
            break
        expr = rhs
    return chain


@dataclass
class Evidence:
    record: dict
    facts: dict


def extract(path: str | Path, line: int, col: int, end_line: int, end_col: int) -> dict:
    """Build the EvidenceRecord for the alert at the given span. Raises Unsupported if it cannot."""
    source = Path(path).read_text()
    tree = ast.parse(source)
    func = _innermost_function(tree, line)
    if func is None:
        raise Unsupported("alert is not inside a function")
    an = Analyzer(tree, func, None)
    target, call, stmt = _locate(func, an.ids, line, col, end_line, end_col)
    an.sink_stmt = stmt
    an.run()
    snap = an.snapshot
    value = an.ev(target, copy.deepcopy(snap.state), (snap.in_loop, snap.in_handler, snap.dead))
    reads = sorted({n.id for n in ast.walk(target) if isinstance(n, ast.Name) and n.id in snap.state})

    # value-dependency slice: every definition the sink value transitively depends on
    relevant, frontier = set(), [d for r in reads for d in snap.state[r].defs]
    while frontier:
        d = frontier.pop()
        if d in relevant or d not in an.defs:
            continue
        relevant.add(d)
        frontier.extend(an.defs[d].depends)
    rel_defs = [an.defs[d] for d in sorted(relevant, key=lambda x: (an.defs[x].line, x))]

    incomplete = []
    if snap.dead:
        pass
    incomplete += sorted(f for f in an.flags if f.startswith("unsupported"))
    kind = _value_kind(value)
    if kind == "unknown":
        incomplete.append("sink value depends on unmodelled code")

    tainted_defs = [d.id for d in rel_defs if worst(d.values) is TAINT]
    pruned_tainted = [d.id for d in an.defs.values() if d.dead and worst(d.values) is TAINT]
    direct_source = _direct_source(an, target)
    sink_defs = [d for r in reads for d in snap.state[r].defs]
    conds = []
    for c in snap.conds:
        guarded = {d for ds in c.reads.values() for d in ds}
        on_value = bool(guarded & relevant)
        uncovered = _uncovered_tainted(an, sink_defs, guarded)
        conds.append({"id": c.id, "condition": opaque(c.code), "polarity_to_reach_sink": c.polarity,
                      "kind": c.kind, "reads": c.reads, "guards_sink_value": on_value,
                      "covers_all_tainted_flows": on_value and not uncovered and not direct_source,
                      "uncovered_tainted_definitions": sorted(uncovered)})
    contained = _containment(an, snap, target)
    facts = {
        "sink_unreachable": snap.dead,
        "sink_value_kind": kind,                     # constant | trusted | unknown | tainted
        "sink_value": opaque(show(value)),
        "complete": not incomplete,
        "incomplete_reasons": sorted(set(incomplete)),
        "tainted_definitions": tainted_defs,
        "pruned_tainted_definitions": pruned_tainted,
        "containment_guards": contained,
        "safe_api": [],
    }
    record = {
        "file_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "function": "handler",
        "sink": {"statement": an.sid(stmt), "line": line, "api": _sink_name(an, call, target),
                 "argument": opaque(ast.unparse(target)), "reads": {r: sorted(snap.state[r].defs) for r in reads}},
        "nodes": [{**n, "code": opaque(n["code"])[:200]} for n in an.nodes],
        "definitions": [{"id": d.id, "var": d.var, "line": d.line, "code": opaque(d.code)[:200],
                         "kind": d.kind, "value": opaque(show(d.values)),
                         "tainted": worst(d.values) is TAINT, "depends_on": d.depends,
                         "in_loop": d.in_loop, "in_exception_handler": d.in_handler, "on_infeasible_path": d.dead,
                         "in_sink_slice": d.id in relevant}
                        for d in sorted(an.defs.values(), key=lambda x: (x.line, x.id)) if d.id != "params"],
        "branches": [{**b, "condition": opaque(b["condition"])} for b in an.branches],
        "path_conditions_at_sink": conds,
        "transformations": _transformations(an, snap, target),
        "facts": facts,
    }
    return record


def function_source(path: str | Path, line: int) -> str:
    """Display source of the enclosing function, with benchmark IDs made opaque (shared by L and E)."""
    source = Path(path).read_text()
    func = _innermost_function(ast.parse(source), line)
    lines = source.splitlines()[func.lineno - 1 - len(func.decorator_list):func.end_lineno]
    numbered = [f"{func.lineno - len(func.decorator_list) + i:4d}  {opaque(l)}" for i, l in enumerate(lines)]
    return "\n".join(numbered)
