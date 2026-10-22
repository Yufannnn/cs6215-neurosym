import os
import os.path
import pathlib
import re
import hashlib
import logging
import urllib.parse
from flask import request, abort, send_file, send_from_directory

ROOT = "/srv/app/files"
log = logging.getLogger(__name__)

def handler():
    name = request.args.get("f", "")
    candidate = os.path.realpath(os.path.join(ROOT, name))
    if os.path.commonpath([ROOT, candidate]) != ROOT:
        abort(403)
    return open(os.path.join(ROOT, urllib.parse.unquote(name))).read()
