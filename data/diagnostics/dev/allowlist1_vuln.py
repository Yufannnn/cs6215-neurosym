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

BLOCKED = {"secret.txt", "passwd"}


def handler():
    name = request.args.get("f", "")
    if name in BLOCKED:
        abort(403)
    return open(os.path.join(ROOT, name)).read()
