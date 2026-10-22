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
    raw = request.args.get("f", "")
    if ".." in raw:
        abort(400)
    name = urllib.parse.unquote(raw)
    return open(f"{ROOT}/{name}").read()
