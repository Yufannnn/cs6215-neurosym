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
    kind = "a"
    match kind:
        case "a":
            name = "a.txt"
        case _:
            name = request.args.get("f", "b.txt")
    return os.path.exists(os.path.join(ROOT, name))
