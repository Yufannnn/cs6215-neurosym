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

DEBUG = True


def handler():
    name = "index.txt"
    if DEBUG:
        name = request.args.get("f", "index.txt")
    return open(os.path.join(ROOT, name)).read()
