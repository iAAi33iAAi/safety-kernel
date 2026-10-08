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
