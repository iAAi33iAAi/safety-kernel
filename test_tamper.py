"""Tamper detection test — modifies a proof file and expects verification to fail."""
import json
import os
import sys


def main():
    proof_files = [f for f in os.listdir(".") if f.startswith("proof_") and f.endswith(".json")]
    if not proof_files:
        print("No proof files found — run 'sk run hello.py' first")
        sys.exit(1)

    path = proof_files[0]
    with open(path) as f:
        proof = json.load(f)

    # Tamper with stdout
    proof["stdout"] = "TAMPERED OUTPUT\n"
    tampered_path = "tampered_proof.json"
    with open(tampered_path, "w") as f:
        json.dump(proof, f, indent=2)

    print(f"Tampered proof written to {tampered_path}")
    print("Now run: sk verify tampered_proof.json")
    print("Expected: VERIFICATION FAILED")


if __name__ == "__main__":
    main()
