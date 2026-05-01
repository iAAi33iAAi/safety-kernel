"""Comprehensive automated test suite for SK CLI."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import shutil


PASS = 0
FAIL = 0
PYTHONPATH = os.path.dirname(os.path.abspath(__file__))


def run_sk(args: list[str], cwd: str = None) -> subprocess.CompletedProcess:
    """Run sk CLI as a subprocess."""
    cmd = [sys.executable, "-m", "sk.cli"] + args
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHONPATH
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env=env)


def check(name: str, condition: bool, detail: str = ""):
    """Assert a test condition."""
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS: {name}")
    else:
        FAIL += 1
        print(f"  FAIL: {name}{f' — {detail}' if detail else ''}")


def test_help():
    """Test: sk with no args shows help and exits 0."""
    print("\n=== TEST: Help output ===")
    r = run_sk([])
    check("exits 0", r.returncode == 0)
    check("shows version", "v0.1.0" in r.stdout)
    check("shows usage", "sk run" in r.stdout and "sk verify" in r.stdout)


def test_unknown_command():
    """Test: sk with unknown command exits 1."""
    print("\n=== TEST: Unknown command ===")
    r = run_sk(["foobar", "x"])
    check("exits 1", r.returncode == 1)
    check("shows error", "Unknown command" in r.stdout)


def test_run_missing_script():
    """Test: sk run on nonexistent file exits 1."""
    print("\n=== TEST: Run missing script ===")
    r = run_sk(["run", "/tmp/nonexistent_sk_test_script.py"])
    check("exits 1", r.returncode == 1)
    check("shows error", "not found" in r.stdout)


def test_run_and_verify():
    """Test: full run + verify cycle."""
    print("\n=== TEST: Run and verify ===")
    tmpdir = tempfile.mkdtemp(prefix="sk_test_")
    try:
        # Create test script
        script = os.path.join(tmpdir, "test_script.py")
        with open(script, "w") as f:
            f.write('print("SK test output 42")\n')

        # Run
        r = run_sk(["run", script], cwd=tmpdir)
        check("run exits 0", r.returncode == 0, r.stderr)
        check("shows proof generated", "Proof generated:" in r.stdout)
        check("shows script hash", "SK: script" in r.stdout)
        check("shows stdout hash", "SK: stdout" in r.stdout)
        check("shows proof hash", "SK: proof" in r.stdout)
        check("passes through output", "SK test output 42" in r.stdout)

        # Find proof file
        proofs = [f for f in os.listdir(tmpdir) if f.startswith("proof_") and f.endswith(".json")]
        check("proof file created", len(proofs) == 1, f"found {len(proofs)}")
        if not proofs:
            return

        proof_path = os.path.join(tmpdir, proofs[0])
        with open(proof_path) as f:
            proof = json.load(f)

        # Proof structure
        check("has proof_id", "proof_id" in proof)
        check("has sk_version", proof.get("sk_version") == "0.1.0")
        check("has script_hash (64 hex)", len(proof.get("script_hash", "")) == 64)
        check("has stdout_hash (64 hex)", len(proof.get("stdout_hash", "")) == 64)
        check("has stderr_hash (64 hex)", len(proof.get("stderr_hash", "")) == 64)
        check("has proof_hash (64 hex)", len(proof.get("proof_hash", "")) == 64)
        check("has timestamp_start", isinstance(proof.get("timestamp_start"), float))
        check("has timestamp_end", isinstance(proof.get("timestamp_end"), float))
        check("has duration_seconds", isinstance(proof.get("duration_seconds"), float))
        check("has environment", isinstance(proof.get("environment"), dict))
        check("has returncode 0", proof.get("returncode") == 0)
        check("stdout captured", "SK test output 42" in proof.get("stdout", ""))
        check("stderr is empty", proof.get("stderr") == "")

        # Environment fields
        env = proof.get("environment", {})
        check("env.python_version", "python_version" in env)
        check("env.platform", "platform" in env)
        check("env.architecture", "architecture" in env)
        check("env.hostname", "hostname" in env)
        check("env.cwd", "cwd" in env)
        check("env.pid", "pid" in env)

        # Verify
        r2 = run_sk(["verify", proof_path])
        check("verify exits 0", r2.returncode == 0, r2.stdout + r2.stderr)
        check("VERIFICATION PASSED", "VERIFICATION PASSED" in r2.stdout)
        check("shows checks passed", "passed" in r2.stdout)

    finally:
        shutil.rmtree(tmpdir)


def test_tamper_stdout():
    """Test: tampered stdout is detected."""
    print("\n=== TEST: Tamper detection — stdout ===")
    tmpdir = tempfile.mkdtemp(prefix="sk_test_")
    try:
        script = os.path.join(tmpdir, "t.py")
        with open(script, "w") as f:
            f.write('print("original")\n')

        run_sk(["run", script], cwd=tmpdir)
        proofs = [f for f in os.listdir(tmpdir) if f.startswith("proof_")]
        proof_path = os.path.join(tmpdir, proofs[0])

        with open(proof_path) as f:
            proof = json.load(f)
        proof["stdout"] = "TAMPERED\n"
        with open(proof_path, "w") as f:
            json.dump(proof, f, indent=2)

        r = run_sk(["verify", proof_path])
        check("exits 1", r.returncode == 1)
        check("VERIFICATION FAILED", "VERIFICATION FAILED" in r.stdout)
        check("detects proof_hash mismatch", "proof_hash mismatch" in r.stdout)
        check("detects stdout_hash mismatch", "stdout_hash mismatch" in r.stdout)
    finally:
        shutil.rmtree(tmpdir)


def test_tamper_returncode():
    """Test: tampered returncode is detected."""
    print("\n=== TEST: Tamper detection — returncode ===")
    tmpdir = tempfile.mkdtemp(prefix="sk_test_")
    try:
        script = os.path.join(tmpdir, "t.py")
        with open(script, "w") as f:
            f.write('print("ok")\n')

        run_sk(["run", script], cwd=tmpdir)
        proofs = [f for f in os.listdir(tmpdir) if f.startswith("proof_")]
        proof_path = os.path.join(tmpdir, proofs[0])

        with open(proof_path) as f:
            proof = json.load(f)
        proof["returncode"] = 1  # Fake a failure
        with open(proof_path, "w") as f:
            json.dump(proof, f, indent=2)

        r = run_sk(["verify", proof_path])
        check("exits 1", r.returncode == 1)
        check("detects proof_hash mismatch", "proof_hash mismatch" in r.stdout)
    finally:
        shutil.rmtree(tmpdir)


def test_tamper_script():
    """Test: modified script after execution is detected."""
    print("\n=== TEST: Tamper detection — script modified ===")
    tmpdir = tempfile.mkdtemp(prefix="sk_test_")
    try:
        script = os.path.join(tmpdir, "t.py")
        with open(script, "w") as f:
            f.write('print("v1")\n')

        run_sk(["run", script], cwd=tmpdir)
        proofs = [f for f in os.listdir(tmpdir) if f.startswith("proof_")]
        proof_path = os.path.join(tmpdir, proofs[0])

        # Modify script after execution
        with open(script, "w") as f:
            f.write('print("v2 BACKDOOR")\n')

        r = run_sk(["verify", proof_path])
        check("exits 1", r.returncode == 1)
        check("detects script change", "script_hash mismatch" in r.stdout)
    finally:
        shutil.rmtree(tmpdir)


def test_missing_field():
    """Test: removing a required field is detected."""
    print("\n=== TEST: Tamper detection — missing field ===")
    tmpdir = tempfile.mkdtemp(prefix="sk_test_")
    try:
        script = os.path.join(tmpdir, "t.py")
        with open(script, "w") as f:
            f.write('print("x")\n')

        run_sk(["run", script], cwd=tmpdir)
        proofs = [f for f in os.listdir(tmpdir) if f.startswith("proof_")]
        proof_path = os.path.join(tmpdir, proofs[0])

        with open(proof_path) as f:
            proof = json.load(f)
        del proof["environment"]
        with open(proof_path, "w") as f:
            json.dump(proof, f, indent=2)

        r = run_sk(["verify", proof_path])
        check("exits 1", r.returncode == 1)
        check("detects missing field", "missing required fields" in r.stdout)
    finally:
        shutil.rmtree(tmpdir)


def test_script_missing_on_verify():
    """Test: verify warns when script no longer exists on disk."""
    print("\n=== TEST: Script missing on verify ===")
    tmpdir = tempfile.mkdtemp(prefix="sk_test_")
    try:
        script = os.path.join(tmpdir, "t.py")
        with open(script, "w") as f:
            f.write('print("temp")\n')

        run_sk(["run", script], cwd=tmpdir)
        proofs = [f for f in os.listdir(tmpdir) if f.startswith("proof_")]
        proof_path = os.path.join(tmpdir, proofs[0])

        os.remove(script)

        r = run_sk(["verify", proof_path])
        check("still exits 0 (warn not fail)", r.returncode == 0)
        check("shows warning", "WARN" in r.stdout)
        check("VERIFICATION PASSED", "VERIFICATION PASSED" in r.stdout)
    finally:
        shutil.rmtree(tmpdir)


def test_failing_script():
    """Test: sk run captures nonzero exit code correctly."""
    print("\n=== TEST: Failing script ===")
    tmpdir = tempfile.mkdtemp(prefix="sk_test_")
    try:
        script = os.path.join(tmpdir, "fail.py")
        with open(script, "w") as f:
            f.write('import sys\nprint("about to fail")\nsys.exit(1)\n')

        r = run_sk(["run", script], cwd=tmpdir)
        check("sk itself exits 0", r.returncode == 0, f"got {r.returncode}")
        check("proof generated", "Proof generated:" in r.stdout)
        check("shows exit code 1", "exit code = 1" in r.stdout)

        proofs = [f for f in os.listdir(tmpdir) if f.startswith("proof_")]
        proof_path = os.path.join(tmpdir, proofs[0])
        with open(proof_path) as f:
            proof = json.load(f)
        check("returncode is 1", proof.get("returncode") == 1)

        r2 = run_sk(["verify", proof_path])
        check("verify still passes", r2.returncode == 0)
    finally:
        shutil.rmtree(tmpdir)


def test_stderr_capture():
    """Test: stderr is captured and hashed correctly."""
    print("\n=== TEST: Stderr capture ===")
    tmpdir = tempfile.mkdtemp(prefix="sk_test_")
    try:
        script = os.path.join(tmpdir, "err.py")
        with open(script, "w") as f:
            f.write('import sys\nprint("out")\nprint("err msg", file=sys.stderr)\n')

        run_sk(["run", script], cwd=tmpdir)
        proofs = [f for f in os.listdir(tmpdir) if f.startswith("proof_")]
        proof_path = os.path.join(tmpdir, proofs[0])

        with open(proof_path) as f:
            proof = json.load(f)
        check("stderr captured", "err msg" in proof.get("stderr", ""))
        check("stderr_hash is correct",
              hashlib.sha256(proof["stderr"].encode()).hexdigest() == proof["stderr_hash"])

        r = run_sk(["verify", proof_path])
        check("verify passes", r.returncode == 0)
    finally:
        shutil.rmtree(tmpdir)


def test_filename_uniqueness():
    """Test: two runs in the same second produce different filenames."""
    print("\n=== TEST: Filename uniqueness ===")
    tmpdir = tempfile.mkdtemp(prefix="sk_test_")
    try:
        script = os.path.join(tmpdir, "quick.py")
        with open(script, "w") as f:
            f.write('print("fast")\n')

        run_sk(["run", script], cwd=tmpdir)
        run_sk(["run", script], cwd=tmpdir)

        proofs = [f for f in os.listdir(tmpdir) if f.startswith("proof_") and f.endswith(".json")]
        check("two distinct proof files", len(proofs) == 2, f"found {len(proofs)}: {proofs}")
    finally:
        shutil.rmtree(tmpdir)


def test_verify_bad_json():
    """Test: verify handles corrupt JSON gracefully."""
    print("\n=== TEST: Verify corrupt JSON ===")
    tmpdir = tempfile.mkdtemp(prefix="sk_test_")
    try:
        bad_path = os.path.join(tmpdir, "bad.json")
        with open(bad_path, "w") as f:
            f.write("NOT VALID JSON {{{")

        r = run_sk(["verify", bad_path])
        check("exits 1", r.returncode == 1)
        check("shows JSON error", "invalid JSON" in r.stdout or "invalid JSON" in r.stderr)
    finally:
        shutil.rmtree(tmpdir)


def test_verify_missing_file():
    """Test: verify handles missing proof file gracefully."""
    print("\n=== TEST: Verify missing file ===")
    r = run_sk(["verify", "/tmp/nonexistent_proof_abc123.json"])
    check("exits 1", r.returncode == 1)
    check("shows error", "not found" in r.stdout)


def test_bash_script():
    """Test: .sh scripts run with bash."""
    print("\n=== TEST: Bash script ===")
    tmpdir = tempfile.mkdtemp(prefix="sk_test_")
    try:
        script = os.path.join(tmpdir, "test.sh")
        with open(script, "w") as f:
            f.write('#!/bin/bash\necho "bash works"\n')

        r = run_sk(["run", script], cwd=tmpdir)
        check("run succeeds", r.returncode == 0)
        check("bash output captured", "bash works" in r.stdout)

        proofs = [f for f in os.listdir(tmpdir) if f.startswith("proof_")]
        if proofs:
            r2 = run_sk(["verify", os.path.join(tmpdir, proofs[0])])
            check("verify passes", r2.returncode == 0)
    finally:
        shutil.rmtree(tmpdir)


# === RUN ALL TESTS ===
if __name__ == "__main__":
    print("=" * 60)
    print("SK CLI — Comprehensive Test Suite")
    print("=" * 60)

    test_help()
    test_unknown_command()
    test_run_missing_script()
    test_run_and_verify()
    test_tamper_stdout()
    test_tamper_returncode()
    test_tamper_script()
    test_missing_field()
    test_script_missing_on_verify()
    test_failing_script()
    test_stderr_capture()
    test_filename_uniqueness()
    test_verify_bad_json()
    test_verify_missing_file()
    test_bash_script()

    print()
    print("=" * 60)
    print(f"RESULTS: {PASS} passed, {FAIL} failed, {PASS + FAIL} total")
    print("=" * 60)

    if FAIL > 0:
        print("STATUS: SOME TESTS FAILED — DO NOT PUSH")
        sys.exit(1)
    else:
        print("STATUS: ALL TESTS PASSED — READY TO PUSH")
        sys.exit(0)
