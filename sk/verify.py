"""Strict proof verification."""
import json
import math
import os
import re
import sys

from sk.proof import canonical_proof_json, hash_bytes, hash_file, load_proof


def _is_sha256_hex(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def verify_proof(path: str):
    """Verify a proof file for integrity and malformed/ambiguous data."""
    if not os.path.isfile(path):
        print(f"Error: proof file not found: {path}")
        sys.exit(1)

    try:
        proof = load_proof(path)
    except (json.JSONDecodeError, ValueError, OSError, UnicodeDecodeError) as e:
        print(f"Error: invalid JSON or proof document: {e}")
        sys.exit(1)

    errors = []
    warnings = []
    checks_passed = 0
    checks_total = 0

    # 1. Verify proof hash (seal integrity).
    checks_total += 1
    original_hash = proof.get("proof_hash", "")
    temp = dict(proof)
    temp.pop("proof_hash", None)
    try:
        canonical = canonical_proof_json(temp)
        recomputed = hash_bytes(canonical.encode("utf-8"))
    except (TypeError, ValueError) as e:
        errors.append(f"proof cannot be canonically serialized: {e}")
    else:
        if not _is_sha256_hex(original_hash):
            errors.append("proof_hash must be 64 lowercase hexadecimal characters")
        elif recomputed != original_hash:
            errors.append("proof_hash mismatch — proof file has been tampered with")
        else:
            checks_passed += 1

    # 2. Verify stdout hash and type.
    checks_total += 1
    stdout = proof.get("stdout")
    expected_stdout_hash = proof.get("stdout_hash", "")
    if not isinstance(stdout, str):
        errors.append("stdout must be a string")
    elif not _is_sha256_hex(expected_stdout_hash):
        errors.append("stdout_hash must be 64 lowercase hexadecimal characters")
    elif hash_bytes(stdout.encode("utf-8")) != expected_stdout_hash:
        errors.append("stdout_hash mismatch — stdout has been modified")
    else:
        checks_passed += 1

    # 3. Verify stderr hash and type.
    checks_total += 1
    stderr = proof.get("stderr")
    expected_stderr_hash = proof.get("stderr_hash", "")
    if not isinstance(stderr, str):
        errors.append("stderr must be a string")
    elif not _is_sha256_hex(expected_stderr_hash):
        errors.append("stderr_hash must be 64 lowercase hexadecimal characters")
    elif hash_bytes(stderr.encode("utf-8")) != expected_stderr_hash:
        errors.append("stderr_hash mismatch — stderr has been modified")
    else:
        checks_passed += 1

    # 4. Verify script hash (if script still exists on disk).
    script_path = proof.get("script", "")
    expected_script_hash = proof.get("script_hash", "")
    if not isinstance(script_path, str):
        errors.append("script must be a string")
    elif not _is_sha256_hex(expected_script_hash):
        errors.append("script_hash must be 64 lowercase hexadecimal characters")
    elif os.path.isfile(script_path):
        checks_total += 1
        try:
            actual_script_hash = hash_file(script_path)
            if actual_script_hash != expected_script_hash:
                errors.append(
                    f"script_hash mismatch — {script_path} has changed since execution"
                )
            else:
                checks_passed += 1
        except OSError as e:
            errors.append(f"could not read script for hash check: {e}")
    else:
        warnings.append(f"script not found at {script_path} — skipping script hash check")

    # 5. Required fields and basic schema validation.
    checks_total += 1
    required = [
        "proof_id", "sk_version", "script", "script_hash", "stdout", "stderr",
        "returncode", "stdout_hash", "stderr_hash", "timestamp_start",
        "timestamp_end", "duration_seconds", "proof_hash", "environment",
    ]
    schema_errors_before = len(errors)
    missing = [field for field in required if field not in proof]
    if missing:
        errors.append(f"missing required fields: {', '.join(missing)}")

    if not isinstance(proof.get("proof_id"), str) or not proof.get("proof_id"):
        errors.append("proof_id must be a non-empty string")
    if not isinstance(proof.get("sk_version"), str) or not proof.get("sk_version"):
        errors.append("sk_version must be a non-empty string")
    if isinstance(proof.get("returncode"), bool) or not isinstance(proof.get("returncode"), int):
        errors.append("returncode must be an integer")
    if not isinstance(proof.get("environment"), dict):
        errors.append("environment must be an object")

    numeric_fields = ("timestamp_start", "timestamp_end", "duration_seconds")
    for field in numeric_fields:
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

    if len(errors) == schema_errors_before:
        checks_passed += 1

    # Report.
    print(f"SK Verify: {path}")
    print(f"  proof_id:   {proof.get('proof_id', 'N/A')}")
    print(f"  script:     {proof.get('script', 'N/A')}")
    print(f"  exit code:  {proof.get('returncode', 'N/A')}")
    print(f"  duration:   {proof.get('duration_seconds', 'N/A')}s")
    print(f"  checks:     {checks_passed}/{checks_total} passed")
    print()

    for warning in warnings:
        print(f"  WARN: {warning}")

    if errors:
        for error in errors:
            print(f"  FAIL: {error}")
        print()
        print("VERIFICATION FAILED")
        sys.exit(1)

    print("  Integrity checks passed.")
    print()
    print("VERIFICATION PASSED")
