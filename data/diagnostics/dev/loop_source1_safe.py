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
    name = "index.txt"
    for candidate in ["a.txt", "b.txt"]:
        if candidate.startswith("b"):
            name = candidate
            break
    return open(os.path.join(ROOT, name)).read()
