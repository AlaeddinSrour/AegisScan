import os
import requests


def fetch_healthcheck():
    return requests.get("https://status.example.com/health", timeout=5)


def read_file(path):
    try:
        with open(path, encoding="utf-8") as source:
            return source.read()
    except FileNotFoundError:
        return ""


def create_exclusively(path):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
