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
    report = request.cookies.get("report", "summary.txt")
    report = "summary.txt"
    return os.path.exists(f"{ROOT}/{report}")
