"""Script execution with proof generation."""
import os
import subprocess
import sys
import time

from sk.proof import build_proof, proof_filename, serialize_proof


def run_script(script_path: str):
    """Execute a script and generate a verifiable proof."""
    if not os.path.isfile(script_path):
        print(f"Error: script not found: {script_path}")
        sys.exit(1)

    # Detect interpreter
    ext = os.path.splitext(script_path)[1].lower()
    if ext == ".py":
        cmd = [sys.executable, script_path]
    elif ext == ".sh":
        cmd = ["bash", script_path]
    elif ext == ".js":
        cmd = ["node", script_path]
    elif ext == ".rb":
        cmd = ["ruby", script_path]
    else:
        # Default: try running directly
        cmd = [script_path]

    print(f"SK: executing {script_path}")
    print(f"SK: command = {' '.join(cmd)}")
    print("---")

    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute max
        )
    except subprocess.TimeoutExpired:
        print("Error: script timed out (300s limit)")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: interpreter or script not found: {e}")
        sys.exit(1)
    except PermissionError as e:
        print(f"Error: permission denied: {e}")
        sys.exit(1)
    end = time.time()

    # Print stdout/stderr pass-through
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)

    print("---")

    # Build proof
    proof = build_proof(
        script_path=script_path,
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.returncode,
        start_time=start,
        end_time=end,
    )

    # Write proof file (unique name — no collision)
    filename = proof_filename(start, proof["proof_id"])
    with open(filename, "w") as f:
        f.write(serialize_proof(proof))

    print(f"SK: exit code = {result.returncode}")
    print(f"SK: duration  = {proof['duration_seconds']:.3f}s")
    print(f"SK: script    = {proof['script_hash'][:16]}...")
    print(f"SK: stdout    = {proof['stdout_hash'][:16]}...")
    print(f"SK: proof     = {proof['proof_hash'][:16]}...")
    print()
    print(f"Proof generated: {filename}")
