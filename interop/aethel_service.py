"""AETHEL Interop v1 evidence adapter for Safety Kernel.

This service exposes hashing and proof-verification evidence only. It never
accepts arbitrary code for execution over HTTP.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import sys

# Ensure direct execution as `python interop/aethel_service.py` can import
# the repository-local proof package even when sys.path[0] is the interop folder.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from sk.proof import canonical_proof_json, strict_json_loads

PROTOCOL = "aethel-interop/1"
SERVICE = "safety-kernel-proof"
VERSION = "0.1.0"
MAX_REQUEST_BYTES = 2_000_000
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _is_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _evidence_envelope(
    request_id: str, proof: dict[str, Any], result: dict[str, Any]
) -> dict[str, Any]:
    subject = proof.get("proof_id", "unknown")
    if not isinstance(subject, str) or not subject:
        subject = "unknown"
    material = {
        "schema": "caios-evidence/v1",
        "authority": "safety-kernel",
        "kind": "execution-proof",
        "subject": subject,
        "status": "PASS" if result["valid"] else "FAIL",
        "checks": result["checks"],
        "passed": result["passed"],
        "errors": list(result["errors"]),
        "warnings": list(result["warnings"]),
    }
    return {
        **material,
        "request_id": request_id,
        "digest": _hash_text(_canonical_json(material)),
    }


def verify_proof_data(proof: dict[str, Any]) -> dict[str, Any]:
    """Validate proof structure and integrity without trusting caller coercions."""
    errors: list[str] = []
    warnings: list[str] = []
    checks = 0
    passed = 0

    if not isinstance(proof, dict):
        return {
            "passed": 0,
            "checks": 1,
            "errors": ["proof must be a JSON object"],
            "warnings": [],
            "valid": False,
        }

    required = {
        "proof_id", "sk_version", "script", "script_hash",
        "stdout", "stderr", "returncode", "stdout_hash", "stderr_hash",
        "timestamp_start", "timestamp_end", "duration_seconds",
        "proof_hash", "environment",
    }
    checks += 1
    missing = sorted(required.difference(proof))
    schema_error_start = len(errors)
    if missing:
        errors.append("missing required fields: " + ", ".join(missing))

    for field in ("proof_id", "sk_version", "script", "stdout", "stderr"):
        if not isinstance(proof.get(field), str):
            errors.append(f"{field} must be a string")
    if not isinstance(proof.get("proof_id"), str) or not proof.get("proof_id"):
        errors.append("proof_id must be a non-empty string")
    if isinstance(proof.get("returncode"), bool) or not isinstance(proof.get("returncode"), int):
        errors.append("returncode must be an integer")
    if not isinstance(proof.get("environment"), dict):
        errors.append("environment must be an object")

    for field in ("proof_hash", "script_hash", "stdout_hash", "stderr_hash"):
        if not _is_sha256_hex(proof.get(field)):
            errors.append(f"{field} must be 64 lowercase hexadecimal characters")

    for field in ("timestamp_start", "timestamp_end", "duration_seconds"):
        value = proof.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            errors.append(f"{field} must be a finite number")

    start_time = proof.get("timestamp_start")
    end_time = proof.get("timestamp_end")
    duration = proof.get("duration_seconds")
    if (
        isinstance(start_time, (int, float)) and not isinstance(start_time, bool)
        and isinstance(end_time, (int, float)) and not isinstance(end_time, bool)
        and isinstance(duration, (int, float)) and not isinstance(duration, bool)
        and math.isfinite(start_time) and math.isfinite(end_time) and math.isfinite(duration)
    ):
        if end_time < start_time:
            errors.append("timestamp_end must not precede timestamp_start")
        if duration < 0:
            errors.append("duration_seconds must not be negative")

    if len(errors) == schema_error_start:
        passed += 1

    # 2. Verify proof seal using the same canonical JSON function as the producer.
    checks += 1
    temp = dict(proof)
    temp.pop("proof_hash", None)
    try:
        canonical = canonical_proof_json(temp)
        recomputed = _hash_text(canonical)
    except (TypeError, ValueError, OverflowError) as exc:
        errors.append(f"proof cannot be canonically serialized: {exc}")
    else:
        if _is_sha256_hex(proof.get("proof_hash")) and recomputed == proof["proof_hash"]:
            passed += 1
        else:
            errors.append("proof_hash mismatch")

    # 3. Verify stdout digest.
    checks += 1
    stdout = proof.get("stdout")
    if isinstance(stdout, str) and _is_sha256_hex(proof.get("stdout_hash")):
        if _hash_text(stdout) == proof["stdout_hash"]:
            passed += 1
        else:
            errors.append("stdout_hash mismatch")
    else:
        errors.append("stdout/stdout_hash malformed")

    # 4. Verify stderr digest.
    checks += 1
    stderr = proof.get("stderr")
    if isinstance(stderr, str) and _is_sha256_hex(proof.get("stderr_hash")):
        if _hash_text(stderr) == proof["stderr_hash"]:
            passed += 1
        else:
            errors.append("stderr_hash mismatch")
    else:
        errors.append("stderr/stderr_hash malformed")

    # 5. Verify script digest when the original path is still available.
    script = proof.get("script")
    script_hash = proof.get("script_hash")
    if isinstance(script, str) and _is_sha256_hex(script_hash) and Path(script).is_file():
        checks += 1
        try:
            actual_script_hash = hashlib.sha256(Path(script).read_bytes()).hexdigest()
        except OSError as exc:
            errors.append(f"could not read script for hash check: {exc}")
        else:
            if actual_script_hash == script_hash:
                passed += 1
            else:
                errors.append("script_hash mismatch")
    else:
        warnings.append("script path unavailable; script hash was not re-read")

    return {
        "passed": passed,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "valid": not errors,
    }


def evaluate(request_id: str, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    if operation == "hash-text":
        value = payload.get("value")
        if not isinstance(value, str):
            return {
                "protocol": PROTOCOL, "service": SERVICE, "version": VERSION,
                "request_id": request_id, "status": "FAIL", "decision": "INVALID_INPUT",
                "reasons": ["value must be a string"], "result": {}, "evidence": {},
            }
        return {
            "protocol": PROTOCOL, "service": SERVICE, "version": VERSION,
            "request_id": request_id, "status": "PASS", "decision": "HASHED",
            "reasons": [], "result": {"sha256": _hash_text(value)},
            "evidence": {"execution": "not performed"},
        }

    if operation in {"proof-evidence", "verify-proof"}:
        proof = payload.get("proof")
        if not isinstance(proof, dict):
            return {
                "protocol": PROTOCOL, "service": SERVICE, "version": VERSION,
                "request_id": request_id, "status": "FAIL", "decision": "INVALID_INPUT",
                "reasons": ["proof must be an object"], "result": {}, "evidence": {},
            }
        result = verify_proof_data(proof)
        envelope = _evidence_envelope(request_id, proof, result)
        if operation == "proof-evidence":
            return {
                "protocol": PROTOCOL, "service": SERVICE, "version": VERSION,
                "request_id": request_id, "status": envelope["status"],
                "decision": "EVIDENCE_EMITTED" if result["valid"] else "EVIDENCE_REJECTED",
                "reasons": result["errors"], "result": {"valid": result["valid"]},
                "evidence": {"caios": envelope},
            }
        return {
            "protocol": PROTOCOL, "service": SERVICE, "version": VERSION,
            "request_id": request_id, "status": "PASS" if result["valid"] else "FAIL",
            "decision": "VERIFIED" if result["valid"] else "REJECTED",
            "reasons": result["errors"], "result": result,
            "evidence": {"execution": "not performed", "caios": envelope},
        }

    return {
        "protocol": PROTOCOL, "service": SERVICE, "version": VERSION,
        "request_id": request_id, "status": "FAIL", "decision": "INVALID_OPERATION",
        "reasons": [f"unsupported operation: {operation}"], "result": {}, "evidence": {},
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/aethel/health":
            self._send(200, {
                "protocol": PROTOCOL, "service": SERVICE, "version": VERSION,
                "request_id": "health", "status": "PASS", "decision": "HEALTHY",
                "reasons": [], "result": {}, "evidence": {"execution_over_http": False},
            })
        elif self.path == "/aethel/capabilities":
            self._send(200, {
                "protocol": PROTOCOL, "service": SERVICE, "version": VERSION,
                "operations": ["hash-text", "verify-proof", "proof-evidence"],
                "execution_over_http": False,
            })
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/aethel/evaluate":
            self._send(404, {"error": "not found"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0:
                self._send(400, {"error": "request body is required"})
                return
            if size > MAX_REQUEST_BYTES:
                self._send(413, {"error": "request body too large"})
                return
            body = strict_json_loads(self.rfile.read(size).decode("utf-8"))
            if not isinstance(body, dict):
                self._send(400, {"error": "request body must be a JSON object"})
                return
            if body.get("protocol") != PROTOCOL:
                self._send(400, {"error": "unsupported protocol"})
                return
            request_id = body.get("request_id")
            operation = body.get("operation")
            payload = body.get("payload", {})
            if not isinstance(request_id, str) or not request_id:
                self._send(400, {"error": "request_id must be a non-empty string"})
                return
            if not isinstance(operation, str) or not operation:
                self._send(400, {"error": "operation must be a non-empty string"})
                return
            if not isinstance(payload, dict):
                self._send(400, {"error": "payload must be an object"})
                return
            self._send(200, evaluate(request_id, operation, payload))
        except (TypeError, ValueError, KeyError, UnicodeDecodeError) as exc:
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
