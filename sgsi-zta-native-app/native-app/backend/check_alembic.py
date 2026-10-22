import os
from alembic.config import Config
from alembic import command

if "TEST_DATABASE_URL" in os.environ and not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]

if not os.environ.get("JWT_SECRET"):
    os.environ["JWT_SECRET"] = "123456789012345678901234567890123456789012345678"
if not os.environ.get("MFA_ENCRYPTION_KEY"):
    os.environ["MFA_ENCRYPTION_KEY"] = "D06cc2sR6itDL38VLiRG1cYgFijoM6nAeaCiPVa_8sE="

cfg = Config("alembic.ini")
print("=== ALEMBIC CURRENT ===")
command.current(cfg)
print("=== ALEMBIC CHECK ===")
command.check(cfg)
print("ALEMBIC VERIFICATION: PASS")
