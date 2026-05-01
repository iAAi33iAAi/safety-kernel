"""Proof generation and integrity primitives."""
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

    # Compute the proof seal — hash of everything above
    canonical = json.dumps(proof, sort_keys=True, ensure_ascii=True)
    proof["proof_hash"] = hash_bytes(canonical.encode("utf-8"))

    return proof


def proof_filename(start_time: float, proof_id: str) -> str:
    """Generate a unique proof filename (no collision on same-second runs)."""
    short_id = proof_id.split("-")[0]
    return f"proof_{int(start_time)}_{short_id}.json"


def serialize_proof(proof: dict) -> str:
    """Serialize proof to JSON."""
    return json.dumps(proof, indent=2, sort_keys=False, ensure_ascii=True)


def load_proof(path: str) -> dict:
    """Load a proof from a JSON file."""
    with open(path, "r") as f:
        return json.load(f)
