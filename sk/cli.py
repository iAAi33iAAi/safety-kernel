"""SK CLI entrypoint."""
import sys
from sk import __version__


def main():
    if len(sys.argv) < 3:
        print(f"SK — Verifiable Execution CLI v{__version__}")
        print()
        print("Usage:")
        print("  sk run <script>        Run a script and generate a proof")
        print("  sk verify <proof.json>  Verify a proof file")
        print()
        print("Examples:")
        print("  sk run build.sh")
        print("  sk run deploy.py")
        print("  sk verify proof_1714430000.json")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "run":
        from sk.runner import run_script
        run_script(sys.argv[2])
    elif cmd == "verify":
        from sk.verify import verify_proof
        verify_proof(sys.argv[2])
    else:
        print(f"Unknown command: {cmd}")
        print("Use 'sk run <script>' or 'sk verify <proof.json>'")
        sys.exit(1)


if __name__ == "__main__":
    main()
