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

def sanitize(name):
    return name.replace("../", "")


def handler():
    return open(os.path.join(ROOT, sanitize(request.args.get("f", "")))).read()
