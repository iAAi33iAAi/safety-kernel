# SK — Verifiable Execution CLI

**Tamper-proof execution proofs for your scripts.**

Run anything. Prove everything. Detect tampering instantly.

## Install

```bash
pip install -e .
```

Or run directly:

```bash
PYTHONPATH=. python3 -m sk.cli run <script>
```

## Usage

### Generate a proof

```bash
sk run build.sh
sk run deploy.py
sk run test_suite.py
```

Output:
```
SK: executing build.sh
SK: command = bash build.sh
---
[your script output here]
---
SK: exit code = 0
SK: duration  = 0.014s
SK: script    = 9cf8eb6adaab4377...
SK: stdout    = da5cc1cd147a099d...
SK: proof     = f10f3aa670c6dcfc...

Proof generated: proof_1714430000.json
```

### Verify a proof

```bash
sk verify proof_1714430000.json
```

Output:
```
SK Verify: proof_1714430000.json
  proof_id:   abb9c0fa-fd4b-4468-985d-1813f68d3e5b
  script:     /path/to/build.sh
  exit code:  0
  duration:   0.014112s
  checks run: 5

  All integrity checks passed.

VERIFICATION PASSED
```

### Detect tampering

If anyone modifies the proof file, stdout, stderr, or the script itself:

```
  FAIL: proof_hash mismatch — proof file has been tampered with
  FAIL: stdout_hash mismatch — stdout has been modified

VERIFICATION FAILED
```

## What's in a proof?

Each proof file contains:

| Field | Description |
|---|---|
| `proof_id` | Unique UUID for this execution |
| `script` | Absolute path to the executed script |
| `script_hash` | SHA-256 of the script at execution time |
| `stdout` / `stderr` | Captured output |
| `stdout_hash` / `stderr_hash` | SHA-256 of each output stream |
| `returncode` | Exit code |
| `timestamp_start` / `timestamp_end` | Execution window |
| `duration_seconds` | Wall-clock duration |
| `environment` | Python version, OS, architecture, hostname |
| `proof_hash` | SHA-256 seal over the entire proof |

## Verification checks

`sk verify` runs 5 integrity checks:

1. **Proof seal** — proof_hash matches recomputed hash of all fields
2. **stdout integrity** — stdout_hash matches actual stdout content
3. **stderr integrity** — stderr_hash matches actual stderr content
4. **Script integrity** — script_hash matches current script on disk (if available)
5. **Required fields** — all mandatory fields are present

## Use cases

- **CI/CD integrity** — prove your build ran exactly as claimed
- **Audit trails** — tamper-proof execution records for compliance
- **Reproducibility** — capture environment + output for debugging
- **Supply chain security** — verify build artifacts weren't modified

## Author

John David Taylor Preston — Founder-Architect
Safety Kernel / Aethel Grid / Undermoon OS / Civics OS

## License

MIT
