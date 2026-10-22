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
    name = request.form.get("doc", "")
    resolved = (pathlib.Path(ROOT) / name).resolve()
    if not resolved.is_relative_to(ROOT):
        abort(400)
    return (pathlib.Path(ROOT) / urllib.parse.unquote(name)).read_text()
