"""Proof verification."""
import json
import os
import sys

from sk.proof import hash_bytes, hash_file, load_proof


def verify_proof(path: str):
    """Verify a proof file for integrity and tampering."""
    if not os.path.isfile(path):
        print(f"Error: proof file not found: {path}")
        sys.exit(1)

    try:
        proof = load_proof(path)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in proof file: {e}")
        sys.exit(1)
    except OSError as e:
        print(f"Error: cannot read proof file: {e}")
        sys.exit(1)

    errors = []
    warnings = []
    checks_passed = 0
    checks_total = 0

    # 1. Verify proof hash (seal integrity)
    checks_total += 1
    original_hash = proof.get("proof_hash", "")
    temp = dict(proof)
    temp.pop("proof_hash", None)
    canonical = json.dumps(temp, sort_keys=True, ensure_ascii=True)
    recomputed = hash_bytes(canonical.encode("utf-8"))
    if recomputed != original_hash:
        errors.append("proof_hash mismatch — proof file has been tampered with")
    else:
        checks_passed += 1

    # 2. Verify stdout hash
    checks_total += 1
    stdout = proof.get("stdout", "")
    expected_stdout_hash = proof.get("stdout_hash", "")
    actual_stdout_hash = hash_bytes(stdout.encode("utf-8"))
    if actual_stdout_hash != expected_stdout_hash:
        errors.append("stdout_hash mismatch — stdout has been modified")
    else:
        checks_passed += 1

    # 3. Verify stderr hash
    checks_total += 1
    stderr = proof.get("stderr", "")
    expected_stderr_hash = proof.get("stderr_hash", "")
    actual_stderr_hash = hash_bytes(stderr.encode("utf-8"))
    if actual_stderr_hash != expected_stderr_hash:
        errors.append("stderr_hash mismatch — stderr has been modified")
    else:
        checks_passed += 1

    # 4. Verify script hash (if script still exists on disk)
    script_path = proof.get("script", "")
    expected_script_hash = proof.get("script_hash", "")
    if os.path.isfile(script_path):
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
            warnings.append(f"could not read script for hash check: {e}")
    else:
        warnings.append(f"script not found at {script_path} — skipping script hash check")

    # 5. Required fields present
    checks_total += 1
    required = [
        "proof_id", "sk_version", "script", "script_hash",
        "stdout_hash", "stderr_hash", "timestamp_start",
        "timestamp_end", "proof_hash", "environment",
    ]
    missing = [f for f in required if f not in proof]
    if missing:
        errors.append(f"missing required fields: {', '.join(missing)}")
    else:
        checks_passed += 1

    # Report
    print(f"SK Verify: {path}")
    print(f"  proof_id:   {proof.get('proof_id', 'N/A')}")
    print(f"  script:     {proof.get('script', 'N/A')}")
    print(f"  exit code:  {proof.get('returncode', 'N/A')}")
    print(f"  duration:   {proof.get('duration_seconds', 'N/A')}s")
    print(f"  checks:     {checks_passed}/{checks_total} passed")
    print()

    for w in warnings:
        print(f"  WARN: {w}")

    if errors:
        for e in errors:
            print(f"  FAIL: {e}")
        print()
        print("VERIFICATION FAILED")
        sys.exit(1)
    else:
        print("  All integrity checks passed.")
        print()
        print("VERIFICATION PASSED")
