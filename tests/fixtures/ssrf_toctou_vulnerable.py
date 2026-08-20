import os
from pathlib import Path
import requests


def fetch_preview(request):
    target = request.args.get("url")
    return requests.get(target, timeout=5)


def read_existing(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as source:
            return source.read()
    return ""


def read_path_object(path: Path):
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""
