"""Proof generation and strict JSON integrity primitives."""
import hashlib
import json
import os
import platform
import sys
import uuid

from sk import __version__


def hash_bytes(data: bytes) -> str:
    """SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_file(path: str) -> str:
    """SHA-256 hash of a file's contents."""
    with open(path, "rb") as f:
        return hash_bytes(f.read())


def _reject_json_constant(value: str):
    """Reject JavaScript-style non-standard numeric constants accepted by json.loads."""
    raise ValueError(f"non-standard JSON constant is forbidden: {value}")


def _reject_duplicate_object_keys(pairs):
    """Reject duplicate keys so all consumers interpret the same object."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def strict_json_loads(text: str):
    """Parse JSON while rejecting duplicate keys and NaN/Infinity extensions."""
    return json.loads(
        text,
        parse_constant=_reject_json_constant,
        object_pairs_hook=_reject_duplicate_object_keys,
    )


def canonical_proof_json(value: dict) -> str:
    """Return the proof-seal serialization; non-finite numbers are not representable."""
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)


def capture_environment() -> dict:
    """Capture execution environment for reproducibility."""
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "cwd": os.getcwd(),
        "pid": os.getpid(),
    }


def build_proof(
    script_path: str,
    stdout: str,
    stderr: str,
    returncode: int,
    start_time: float,
    end_time: float,
) -> dict:
    """Build a complete proof object."""
    script_hash = hash_file(script_path)
    stdout_hash = hash_bytes(stdout.encode("utf-8"))
    stderr_hash = hash_bytes(stderr.encode("utf-8"))

    proof = {
        "proof_id": str(uuid.uuid4()),
        "sk_version": __version__,
        "script": os.path.abspath(script_path),
        "script_hash": script_hash,
        "stdout": stdout,
        "stderr": stderr,
        "returncode": returncode,
        "stdout_hash": stdout_hash,
        "stderr_hash": stderr_hash,
        "timestamp_start": start_time,
        "timestamp_end": end_time,
        "duration_seconds": round(end_time - start_time, 6),
        "environment": capture_environment(),
    }

    # Keep the historical key ordering/spacing; reject non-finite values.
    proof["proof_hash"] = hash_bytes(canonical_proof_json(proof).encode("utf-8"))
    return proof


def proof_filename(start_time: float, proof_id: str) -> str:
    """Generate a unique proof filename (no collision on same-second runs)."""
    short_id = proof_id.split("-")[0]
    return f"proof_{int(start_time)}_{short_id}.json"


def serialize_proof(proof: dict) -> str:
    """Serialize proof JSON, rejecting NaN and Infinity rather than emitting invalid JSON."""
    return json.dumps(proof, indent=2, sort_keys=False, ensure_ascii=True, allow_nan=False)


def load_proof(path: str) -> dict:
    """Load one JSON proof object using strict duplicate-key/non-finite rejection."""
    with open(path, "r", encoding="utf-8") as f:
        value = strict_json_loads(f.read())
    if not isinstance(value, dict):
        raise ValueError("proof document must be a JSON object")
    return value
