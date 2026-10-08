"""AETHEL Interop v1 evidence adapter for Safety Kernel.

This service exposes hashing and proof-verification evidence only. It never
accepts arbitrary code for execution over HTTP.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

PROTOCOL = "aethel-interop/1"
SERVICE = "safety-kernel-proof"
VERSION = "0.1.0"

def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def verify_proof_data(proof: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    checks = 0
    passed = 0

    expected = str(proof.get("proof_hash", ""))
    temp = dict(proof)
    temp.pop("proof_hash", None)
    recomputed = _hash_text(json.dumps(temp, sort_keys=True, ensure_ascii=True))
    checks += 1
    if recomputed == expected:
        passed += 1
    else:
        errors.append("proof_hash mismatch")

    for field, label in (("stdout", "stdout_hash"), ("stderr", "stderr_hash")):
        checks += 1
        actual = _hash_text(str(proof.get(field, "")))
        if actual == str(proof.get(label, "")):
            passed += 1
        else:
            errors.append(f"{label} mismatch")

    required = {"proof_id", "sk_version", "script", "script_hash", "stdout_hash", "stderr_hash", "timestamp_start", "timestamp_end", "environment"}
    checks += 1
    missing = sorted(required.difference(proof))
    if not missing:
        passed += 1
    else:
        errors.append("missing required fields: " + ", ".join(missing))

    script = str(proof.get("script", ""))
    expected_script_hash = str(proof.get("script_hash", ""))
    path = Path(script)
    if path.is_file():
        checks += 1
        actual_script_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_script_hash == expected_script_hash:
            passed += 1
        else:
            errors.append("script_hash mismatch")
    else:
        warnings.append("script path not available to verifier; script hash was not re-read")

    return {"passed": passed, "checks": checks, "errors": errors, "warnings": warnings, "valid": not errors}

def evaluate(request_id: str, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    if operation == "hash-text":
        value = payload.get("value")
        if not isinstance(value, str):
            return {"protocol": PROTOCOL, "service": SERVICE, "version": VERSION, "request_id": request_id, "status": "FAIL", "decision": "INVALID_INPUT", "reasons": ["value must be a string"], "result": {}, "evidence": {}}
        return {"protocol": PROTOCOL, "service": SERVICE, "version": VERSION, "request_id": request_id, "status": "PASS", "decision": "HASHED", "reasons": [], "result": {"sha256": _hash_text(value)}, "evidence": {"execution": "not performed"}}
    if operation == "verify-proof":
        proof = payload.get("proof")
        if not isinstance(proof, dict):
            return {"protocol": PROTOCOL, "service": SERVICE, "version": VERSION, "request_id": request_id, "status": "FAIL", "decision": "INVALID_INPUT", "reasons": ["proof must be an object"], "result": {}, "evidence": {}}
        result = verify_proof_data(proof)
        return {"protocol": PROTOCOL, "service": SERVICE, "version": VERSION, "request_id": request_id, "status": "PASS" if result["valid"] else "FAIL", "decision": "VERIFIED" if result["valid"] else "REJECTED", "reasons": result["errors"], "result": result, "evidence": {"execution": "not performed"}}
    return {"protocol": PROTOCOL, "service": SERVICE, "version": VERSION, "request_id": request_id, "status": "FAIL", "decision": "INVALID_OPERATION", "reasons": [f"unsupported operation: {operation}"], "result": {}, "evidence": {}}

class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/aethel/health":
            self._send(200, {"protocol": PROTOCOL, "service": SERVICE, "version": VERSION, "request_id": "health", "status": "PASS", "decision": "HEALTHY", "reasons": [], "result": {}, "evidence": {"execution_over_http": False}})
        elif self.path == "/aethel/capabilities":
            self._send(200, {"protocol": PROTOCOL, "service": SERVICE, "version": VERSION, "operations": ["hash-text", "verify-proof"], "execution_over_http": False})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/aethel/evaluate":
            self._send(404, {"error": "not found"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(size).decode("utf-8"))
            if body.get("protocol") != PROTOCOL:
                self._send(400, {"error": "unsupported protocol"})
                return
            self._send(200, evaluate(str(body["request_id"]), str(body.get("operation", "")), dict(body.get("payload", {}))))
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})

    def log_message(self, format: str, *args: Any) -> None:
        return

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8105)
    args = parser.parse_args()
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()

if __name__ == "__main__":
    main()
