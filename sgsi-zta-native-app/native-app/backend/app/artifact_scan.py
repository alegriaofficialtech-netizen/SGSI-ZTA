"""Check exported public artifacts against DB MFA secrets without exporting secrets."""

import json
import sys

from sqlalchemy import select

from app.auth.mfa_service import cipher, decrypt_secret
from app.config import get_settings
from app.database import SessionLocal
from app.models import MfaChallenge, MfaCredential


def main():
    payload = json.load(sys.stdin)
    config = get_settings()
    values = [config.jwt_secret.get_secret_value(), config.mfa_encryption_key.get_secret_value()]
    if config.demo_password:
        values.append(config.demo_password.get_secret_value())
    with SessionLocal() as db:
        secrets_at_rest = list(db.scalars(select(MfaCredential.secret_encrypted)))
        secrets_at_rest += list(
            db.scalars(
                select(MfaChallenge.secret_encrypted).where(
                    MfaChallenge.secret_encrypted.is_not(None)
                )
            )
        )
    values += [decrypt_secret(value) for value in secrets_at_rest]
    if payload.get("encrypted_recovery_handoff"):
        handoff = json.loads(cipher().decrypt(payload["encrypted_recovery_handoff"].encode()))
        for codes in handoff.values():
            values.extend(codes)
            values.extend(code.replace("-", "") for code in codes)
    problems = [
        name
        for name, content in payload["files"].items()
        if any(value in content for value in values)
    ]
    if problems:
        print(json.dumps({"status": "FAIL", "files": problems}))
        raise SystemExit(1)
    print(
        json.dumps(
            {
                "status": "PASS",
                "scope": "source/build/logs/evidence vs actual server MFA and recovery secrets",
                "files_checked": len(payload["files"]),
            }
        )
    )


if __name__ == "__main__":
    main()
