import json

import pytest

from sk.proof import canonical_proof_json, hash_bytes, strict_json_loads
from interop.aethel_service import evaluate, verify_proof_data


def _valid_proof():
    proof = {
        "proof_id": "evidence-1",
        "sk_version": "0.1",
        "script": "/missing",
        "script_hash": "a" * 64,
        "stdout": "hello",
        "stderr": "",
        "returncode": 0,
        "stdout_hash": hash_bytes(b"hello"),
        "stderr_hash": hash_bytes(b""),
        "timestamp_start": 1,
        "timestamp_end": 2,
        "duration_seconds": 1,
        "environment": {},
    }
    proof["proof_hash"] = hash_bytes(canonical_proof_json(proof).encode("utf-8"))
    return proof


def test_hash_text():
    result = evaluate("r1", "hash-text", {"value": "abc"})
    assert result["result"]["sha256"] == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


def test_invalid_proof_fails_closed():
    result = evaluate("r2", "verify-proof", {"proof": {"proof_hash": "wrong"}})
    assert result["status"] == "FAIL"
    assert result["decision"] == "REJECTED"


def test_verify_proof_rejects_tampered_stdout():
    proof = _valid_proof()
    proof["stdout"] = "tampered"
    result = verify_proof_data(proof)
    assert result["valid"] is False
    assert any("stdout_hash mismatch" in error for error in result["errors"])


def test_proof_evidence_emits_caios_envelope():
    result = evaluate("r3", "proof-evidence", {"proof": _valid_proof()})
    envelope = result["evidence"]["caios"]
    assert result["status"] == "PASS"
    assert envelope["schema"] == "caios-evidence/v1"
    assert envelope["authority"] == "safety-kernel"
    assert envelope["kind"] == "execution-proof"
    assert len(envelope["digest"]) == 64


@pytest.mark.parametrize(
    "raw",
    [
        '{"proof_hash":"first","proof_hash":"second"}',
        '{"value": NaN}',
        '{"value": Infinity}',
        '{"value": -Infinity}',
    ],
)
def test_strict_json_rejects_duplicate_keys_and_nonstandard_numbers(raw):
    with pytest.raises(ValueError):
        strict_json_loads(raw)


def test_interop_verifier_rejects_nonfinite_proof_values_without_crashing():
    proof = _valid_proof()
    proof["extra_metric"] = float("nan")
    result = verify_proof_data(proof)
    assert result["valid"] is False
    assert any("canonically serialized" in error for error in result["errors"])


def test_interop_verifier_rejects_wrong_field_types():
    proof = _valid_proof()
    proof["stdout"] = ["not", "text"]
    result = verify_proof_data(proof)
    assert result["valid"] is False
    assert any("stdout must be a string" in error or "stdout/stdout_hash malformed" in error
               for error in result["errors"])
