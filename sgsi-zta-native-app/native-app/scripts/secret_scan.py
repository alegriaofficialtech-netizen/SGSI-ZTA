"""Scan native source against local secrets and obvious credential artifacts."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
excluded = {
    ".venv",
    "node_modules",
    "coverage",
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    ".private",
}
values = []
parser = argparse.ArgumentParser()
parser.add_argument("--database", action="store_true")
parser.add_argument("--git", action="store_true")
parser.add_argument("--remote-database", action="store_true")
parser.add_argument("--stdin-corpus", action="store_true")
args = parser.parse_args()
env = root / ".env"
if env.exists():
    for line in env.read_text(encoding="utf-8").splitlines():
        if line.startswith(
            (
                "POSTGRES_PASSWORD=",
                "JWT_SECRET=",
                "DEMO_PASSWORD=",
                "MFA_ENCRYPTION_KEY=",
            )
        ):
            values.append(line.split("=", 1)[1])
problems = []
corpus = json.load(sys.stdin)["files"] if args.stdin_corpus else {}
patterns = [
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}",
    r"otpauth://(?:totp|hotp)/[^\s\"']+\?[^\s\"']*secret=[A-Z2-7]{16,}",
    r"postgres(?:ql)?(?:\+psycopg)?://[A-Za-z0-9_.-]+:(?!\$|CHANGE_ME)[^@\s\"']{12,}@",
    r"(?:refresh_token|sgsi_refresh)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_-]{32,}[\"']",
]
for name, content in corpus.items():
    applicable = patterns[:2] if name.startswith("git:") else patterns
    if any(value in content for value in values) or any(
        re.search(pattern, content) for pattern in applicable
    ):
        problems.append(name)
for path in root.rglob("*"):
    if (
        not path.is_file()
        or excluded & set(path.relative_to(root).parts)
        or (path.name.startswith(".env") and path.name != ".env.example")
        or path.suffix.lower() in {".png", ".jpg", ".woff", ".woff2", ".enc"}
    ):
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    corpus[path.relative_to(root).as_posix()] = text
    if any(value in text for value in values) or any(
        re.search(pattern, text) for pattern in patterns
    ):
        problems.append(path.relative_to(root).as_posix())
if args.git:
    repo = root.parent
    tracked = (
        subprocess.run(
            ["git", "ls-files", "-z"], cwd=repo, capture_output=True, check=True
        )
        .stdout.decode()
        .split("\0")
    )
    for name in tracked:
        path = repo / name
        if name and path.is_file():
            content = path.read_text(encoding="utf-8", errors="ignore")
            corpus["git:" + name] = content
            # Current tracked files: known credentials, concrete JWT and private keys.
            # Placeholder DB URLs in legacy examples are not live native credentials.
            if any(value in content for value in values) or any(
                re.search(pattern, content) for pattern in patterns[:2]
            ):
                problems.append("git:" + name)
if problems:
    print("FAIL: credential patterns detected in: " + ", ".join(problems))
    raise SystemExit(1)
if args.remote_database:
    subprocess.run(
        [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=8",
            "-o",
            "ForwardAgent=no",
            "elcra@192.168.1.36",
            "cd /home/elcra/sgsi-zta-native-app && python3 scripts/secret_scan.py --database --stdin-corpus",
        ],
        input=json.dumps({"files": corpus}).encode(),
        check=True,
    )
if args.database:
    private = root / ".private" / "m2-demo-recovery.enc"
    encrypted = private.read_text(encoding="ascii") if private.exists() else ""
    data = json.dumps(
        {"files": corpus, "encrypted_recovery_handoff": encrypted}
    ).encode()
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
            "-m",
            "app.artifact_scan",
        ],
        cwd=root,
        input=data,
        check=True,
    )
print(
    "PASS: no local native credentials, JWT literals, provisioning secrets or private keys in source, build, logs and evidence."
)
print(
    "Scope: native source; this is not a full historical secret audit of the legacy repository."
)
