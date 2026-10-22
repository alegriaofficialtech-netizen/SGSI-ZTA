"""Generate private local demo settings once, never overwrite or print credentials."""

import base64
import os
import secrets
from pathlib import Path

root = Path(__file__).resolve().parents[1]
path = root / ".env"
if path.exists():
    raise SystemExit(".env already exists; nothing overwritten")
template = (root / ".env.example").read_text(encoding="utf-8")
for placeholder, value in {
    "CHANGE_ME_GENERATE_RANDOM": secrets.token_hex(32),
    "CHANGE_ME_GENERATE_FERNET_KEY": base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode(),
    "CHANGE_ME_GENERATE_AT_LEAST_48_RANDOM_CHARACTERS": secrets.token_urlsafe(64),
    "CHANGE_ME_GENERATE_STRONG_SYNTHETIC_PASSWORD": "Demo!Aa9-"
    + secrets.token_urlsafe(24),
}.items():
    template = template.replace(placeholder, value)
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
    output.write(template)
print(
    "Private .env generated. See DEMO_PASSWORD there for synthetic accounts. No secrets printed."
)
