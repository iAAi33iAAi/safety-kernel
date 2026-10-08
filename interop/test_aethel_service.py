from interop.aethel_service import evaluate, verify_proof_data

def test_hash_text():
    result = evaluate("r1", "hash-text", {"value": "abc"})
    assert result["result"]["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_invalid_proof_fails_closed():
    result = evaluate("r2", "verify-proof", {"proof": {"proof_hash": "wrong"}})
    assert result["status"] == "FAIL"
    assert result["decision"] == "REJECTED"

def test_verify_proof_rejects_tampered_stdout():
    proof = {"proof_id":"id","sk_version":"0.1","script":"/missing","script_hash":"x","stdout":"hello","stderr":"","returncode":0,"stdout_hash":"wrong","stderr_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","timestamp_start":1,"timestamp_end":2,"environment":{}}
    result = verify_proof_data(proof)
    assert result["valid"] is False


def test_proof_evidence_emits_caios_envelope():
    from interop.aethel_service import _hash_text

    proof = {
        "proof_id": "evidence-1",
        "sk_version": "0.1",
        "script": "/missing",
        "script_hash": "x",
        "stdout": "hello",
        "stderr": "",
        "returncode": 0,
        "stdout_hash": _hash_text("hello"),
        "stderr_hash": _hash_text(""),
        "timestamp_start": 1,
        "timestamp_end": 2,
        "environment": {},
    }
    proof["proof_hash"] = _hash_text(__import__("json").dumps(proof, sort_keys=True, ensure_ascii=True))
    result = evaluate("r3", "proof-evidence", {"proof": proof})
    envelope = result["evidence"]["caios"]
    assert result["status"] == "PASS"
    assert envelope["schema"] == "caios-evidence/v1"
    assert envelope["authority"] == "safety-kernel"
    assert envelope["kind"] == "execution-proof"
    assert len(envelope["digest"]) == 64
