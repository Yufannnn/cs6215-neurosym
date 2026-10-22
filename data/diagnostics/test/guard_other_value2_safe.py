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
    path = os.path.realpath(os.path.join(ROOT, request.form.get("p", "")))
    if not path.startswith(ROOT + os.sep):
        abort(403)
    os.remove(path)
    return "ok"
