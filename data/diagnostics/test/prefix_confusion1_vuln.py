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
    target = os.path.realpath(os.path.join(ROOT, request.args.get("f", "")))
    if not target.startswith(ROOT):
        abort(403)
    return open(target).read()
