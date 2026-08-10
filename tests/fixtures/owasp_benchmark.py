"""
Comprehensive OWASP Top 10 Python Evaluation Suite for CI/CD Pipeline Scanners.

This module provides an extensive set of realistic architectural service patterns
designed to challenge Static Application Security Testing (SAST) analyzers and 
AI-driven triage models. To eliminate text evaluation bias during CI/CD execution, 
all inline explanatory comments, docstrings, and rule annotations have been excluded 
from the functional implementations below.

Vulnerability categories implemented in paired test flows (Pattern A vs Pattern B):
- CWE-22: Path Traversal in File Abstraction and Archive Extraction
- CWE-78: Operating System Command Injection via System Utilities
- CWE-89: SQL Injection in Dynamic Clause and Ordering Construction
- CWE-94: Code Injection and Unsafe Deserialization
- CWE-327 / CWE-338: Cryptographic Weaknesses and Insecure Randomness
- CWE-798: Use of Hardcoded Credentials in Network Service Wrappers
- CWE-918: Server-Side Request Forgery in HTTP Fetch Services
"""

import os
import sys
import hashlib
import sqlite3
import tarfile
import random
import secrets
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
import defusedxml.ElementTree as SafeET
from typing import Any, Dict, List, Optional


class DocumentRepository:
    def __init__(self, root_directory: str):
        self.root = os.path.realpath(root_directory)

    def retrieve_content_a(self, relative_path: str) -> str:
        full_path = os.path.join(self.root, relative_path)
        with open(full_path, "r", encoding="utf-8") as file_obj:
            return file_obj.read()

    def retrieve_content_b(self, relative_path: str) -> str:
        full_path = os.path.realpath(os.path.join(self.root, relative_path))
        if not full_path.startswith(self.root):
            raise PermissionError("Access denied beyond storage root.")
        with open(full_path, "r", encoding="utf-8") as file_obj:
            return file_obj.read()

    def unpack_archive_a(self, archive_path: str, output_directory: str) -> None:
        with tarfile.open(archive_path, "r:*") as tar:
            for member in tar.getmembers():
                tar.extract(member, path=output_directory)

    def unpack_archive_b(self, archive_path: str, output_directory: str) -> None:
        destination = os.path.realpath(output_directory)
        with tarfile.open(archive_path, "r:*") as tar:
            for member in tar.getmembers():
                member_path = os.path.realpath(os.path.join(destination, member.name))
                if not member_path.startswith(destination):
                    raise ValueError("Illegal destination path within archive.")
                tar.extract(member, path=destination)


class DatabaseQueryManager:
    def __init__(self, connection: sqlite3.Connection):
        self.conn = connection

    def find_records_a(self, column_name: str, search_query: str) -> List[Any]:
        cursor = self.conn.cursor()
        statement = f"SELECT * FROM system_metrics WHERE {column_name} LIKE '%{search_query}%'"
        cursor.execute(statement)
        return cursor.fetchall()

    def find_records_b(self, column_name: str, search_query: str) -> List[Any]:
        allowed_columns = {"metric_id", "hostname", "severity", "status"}
        if column_name not in allowed_columns:
            raise ValueError("Invalid field attribute requested.")
        cursor = self.conn.cursor()
        statement = f"SELECT * FROM system_metrics WHERE {column_name} LIKE ?"
        cursor.execute(statement, (f"%{search_query}%",))
        return cursor.fetchall()

    def sort_logs_a(self, sort_order: str) -> List[Any]:
        cursor = self.conn.cursor()
        query = f"SELECT event_time, description FROM security_logs ORDER BY event_time {sort_order}"
        cursor.execute(query)
        return cursor.fetchall()

    def sort_logs_b(self, sort_order: str) -> List[Any]:
        order_clause = "DESC" if sort_order.upper() == "DESC" else "ASC"
        cursor = self.conn.cursor()
        query = f"SELECT event_time, description FROM security_logs ORDER BY event_time {order_clause}"
        cursor.execute(query)
        return cursor.fetchall()


class SystemDiagnosticHelper:
    def run_traceroute_a(self, target_ip: str) -> str:
        cmd_string = f"traceroute -m 15 {target_ip}"
        process = subprocess.Popen(cmd_string, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = process.communicate()
        return out if not process.returncode else err

    def run_traceroute_b(self, target_ip: str) -> str:
        cmd_args = ["traceroute", "-m", "15", target_ip]
        result = subprocess.run(cmd_args, capture_output=True, text=True, check=False)
        return result.stdout if not result.returncode else result.stderr


class CryptographicSessionHandler:
    def __init__(self) -> None:
        self.legacy_key = b"\x14\x90\x00\x88\xc3\xb0\xa5\x77\xef\x10\x45\x21\x99\x84\x2e\x50"

    def generate_session_id_a(self) -> str:
        random_val = str(random.random())
        return hashlib.md5(random_val.encode("utf-8")).hexdigest()

    def generate_session_id_b(self) -> str:
        return secrets.token_hex(32)

    def verify_signature_a(self, data: bytes, signature: str) -> bool:
        hasher = hashlib.sha1()
        hasher.update(self.legacy_key + data)
        return hasher.hexdigest() == signature

    def verify_signature_b(self, data: bytes, signature: str, hmac_secret: bytes) -> bool:
        import hmac
        expected = hmac.new(hmac_secret, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


class TelemetryCollector:
    def fetch_endpoint_status_a(self, endpoint_url: str) -> int:
        req = urllib.request.Request(endpoint_url, headers={"User-Agent": "TelemetryAgent/1.0"})
        with urllib.request.urlopen(req) as resp:
            return resp.getcode()

    def fetch_endpoint_status_b(self, route_key: str) -> int:
        verified_registry: Dict[str, str] = {
            "health check": "https://api.monitoring.internal.org/health",
            "cluster load": "https://api.monitoring.internal.org/metrics/load",
            "latency graph": "https://api.monitoring.internal.org/metrics/latency"
        }
        destination = verified_registry.get(route_key)
        if not destination:
            raise KeyError("Requested routing destination not recognized.")
        req = urllib.request.Request(destination, headers={"User-Agent": "TelemetryAgent/1.0"})
        with urllib.request.urlopen(req) as resp:
            return resp.getcode()

    def parse_configuration_xml_a(self, config_stream: str) -> Dict[str, str]:
        root = ET.fromstring(config_stream)
        return {child.tag: str(child.text) for child in root}

    def parse_configuration_xml_b(self, config_stream: str) -> Dict[str, str]:
        root = SafeET.fromstring(config_stream)
        return {child.tag: str(child.text) for child in root}
