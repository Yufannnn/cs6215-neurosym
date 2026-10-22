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
    target = os.path.abspath(os.path.join(ROOT, request.form.get("f", "")))
    if target.startswith(ROOT):
        return os.path.exists(target)
    return False
