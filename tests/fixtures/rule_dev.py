"""Rule-development fixtures for the frozen Semgrep policy (not evaluation data).

Each sink line carries `# EXPECT: alert` or `# EXPECT: none`; tests/test_baseline.py checks the rule matches.
"""
import codecs
import configparser
import os
import pathlib
import shutil

import flask
from flask import request, send_file, send_from_directory
from werkzeug.utils import secure_filename

import helpers.separate_request
import helpers.ThingFactory
import helpers.utils

ROOT = "/srv/files"


def builtin_open():
    name = request.args.get("f")
    return open(os.path.join(ROOT, name)).read()  # EXPECT: alert


def fstring_codecs():
    name = request.form.get("f")
    return codecs.open(f"{ROOT}/{name}", "r", "utf-8").read()  # EXPECT: alert


def pathlib_ops():
    p = pathlib.Path(ROOT) / request.headers.get("X-File")
    if p.exists():  # EXPECT: alert
        return p.read_text()  # EXPECT: alert
    return ""


def os_path_probe():
    return os.path.exists(ROOT + "/" + request.cookies.get("f"))  # EXPECT: alert


def destructive_ops():
    target = os.path.join(ROOT, request.args["f"])
    os.remove(target)  # EXPECT: alert
    shutil.copy("/tmp/a", target)  # EXPECT: alert


def flask_send():
    name = request.args.get("f")
    send_file(os.path.join(ROOT, name))  # EXPECT: alert
    return send_from_directory(ROOT, name)  # EXPECT: none


def flask_send_untrusted_dir():
    return send_from_directory(request.args.get("d"), "index.html")  # EXPECT: alert


def list_propagation():
    lst = []
    lst.append(request.args.get("f"))
    return open(lst[0]).read()  # EXPECT: alert


def config_propagation():
    conf = configparser.ConfigParser()
    conf.add_section("s")
    conf.set("s", "k", request.form.get("f"))
    return open(conf.get("s", "k")).read()  # EXPECT: alert


def header_name_loop():
    name = ""
    for h in request.headers.keys():
        name = h
    return open(os.path.join(ROOT, name)).read()  # EXPECT: alert


def wrapper_sources():
    w = helpers.separate_request.request_wrapper(request)
    open(w.get_form_parameter("f"))  # EXPECT: alert
    open(w.get_query_parameter("f"))  # EXPECT: alert
    open(w.get_cookie("f"))  # EXPECT: alert
    open(w.get_safe_value("f"))  # EXPECT: none


def get_parameter_source():
    return open(helpers.utils.get_parameter(request, "f")).read()  # EXPECT: alert


def thing_factory_passthrough():
    thing = helpers.ThingFactory.createThing()
    bar = thing.doSomething(request.args.get("f"))
    return open(bar).read()  # EXPECT: alert


def sanitized():
    name = secure_filename(request.args.get("f"))
    return open(os.path.join(ROOT, name)).read()  # EXPECT: none


def constant_only():
    return open(os.path.join(ROOT, "fixed.txt")).read()  # EXPECT: none


def _helper(path):
    return open(path).read()  # EXPECT: none


def cross_function():
    # Semgrep CE is intraprocedural: the flow into _helper is not reported (documented limitation).
    return _helper(os.path.join(ROOT, request.args.get("f")))
