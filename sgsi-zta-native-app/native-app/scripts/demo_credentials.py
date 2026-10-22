"""Operator-only viewing of encrypted demo recovery handoff. Never run in reports."""

import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
encrypted = (root / ".private" / "m2-demo-recovery.enc").read_bytes()
code = "import sys,json; from app.auth.mfa_service import cipher; data=json.loads(cipher().decrypt(sys.stdin.buffer.read())); print(json.dumps(data,indent=2))"
subprocess.run(
    [
        "docker",
        "--context",
        "default",
        "compose",
        "--project-name",
        "sgsi-zta-native",
        "exec",
        "-T",
        "backend",
        "python",
        "-c",
        code,
    ],
    cwd=root,
    input=encrypted,
    check=True,
)
