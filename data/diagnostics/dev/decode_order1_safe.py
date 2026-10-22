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
    name = urllib.parse.unquote(request.args.get("f", ""))
    target = os.path.realpath(os.path.join(ROOT, name))
    if os.path.commonpath([ROOT, target]) != ROOT:
        abort(400)
    return open(target).read()
