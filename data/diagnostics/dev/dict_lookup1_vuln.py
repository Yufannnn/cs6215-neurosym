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

FILES = {"a": "a.txt", "b": "b.txt"}


def handler():
    key = request.args.get("k", "a")
    return open(os.path.join(ROOT, FILES.get(key, key))).read()
