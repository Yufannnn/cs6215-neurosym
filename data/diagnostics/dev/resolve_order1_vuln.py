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
    target = pathlib.Path(ROOT) / request.args.get("f", "")
    if not target.is_relative_to(ROOT):
        abort(403)
    return target.read_text()
