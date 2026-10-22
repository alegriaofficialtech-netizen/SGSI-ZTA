"""Add the server-only Fernet key without changing any existing M0-M1 secrets."""

import base64
import os
import secrets
from pathlib import Path

path = Path(__file__).resolve().parents[1] / ".env"
text = path.read_text(encoding="utf-8")
if not any(line.startswith("MFA_ENCRYPTION_KEY=") for line in text.splitlines()):
    with path.open("a", encoding="utf-8", newline="\n") as output:
        output.write(
            "\nMFA_ENCRYPTION_KEY="
            + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
            + "\n"
        )
    if os.name != "nt":
        path.chmod(0o600)
    print(
        "MFA encryption key generated in the private server environment. No secrets printed."
    )
else:
    print("Existing MFA key preserved.")
