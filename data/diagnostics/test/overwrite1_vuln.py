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
    if name.endswith(".txt"):
        name = "default.txt"
    return open(os.path.join(ROOT, name)).read()
