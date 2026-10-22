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
    base = os.path.basename(request.args.get("f", ""))
    if base in ("", ".", ".."):
        return False
    return os.path.exists(os.path.join(ROOT, base))
