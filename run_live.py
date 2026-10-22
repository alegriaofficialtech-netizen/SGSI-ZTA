import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("C:/Users/elcra/Desktop/sgcopia")
BACKEND = ROOT / "sgsi-zta-native-app/native-app/backend"
FRONTEND = ROOT / "sgsi-zta-native-app/native-app/frontend"
CLOUDFLARED = Path("C:/Users/elcra/Desktop/cloudflared.exe")
PYTHON_EXE = BACKEND / ".venv/Scripts/python.exe"
DB_PATH = (BACKEND / "sgsi_demo.db").as_posix()
TUNNEL_LOG = ROOT / "tunnel.log"

env = os.environ.copy()
env["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
env["JWT_SECRET"] = "super_secret_jwt_key_local_demo_1234567890_min_length"
env["MFA_ENCRYPTION_KEY"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
env["DEMO_PASSWORD"] = "Demo!Aa9-12345678"
env["COOKIE_SECURE"] = "false"
env["ALLOWED_HOSTS"] = '["*"]'

print("[1/3] Starting backend on port 8000...", flush=True)
backend_proc = subprocess.Popen(
    [
        str(PYTHON_EXE),
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8000",
    ],
    cwd=str(BACKEND),
    env=env,
)

time.sleep(2)

print("[2/3] Starting frontend on port 5173...", flush=True)
frontend_proc = subprocess.Popen(
    ["npm.cmd", "run", "dev"],
    cwd=str(FRONTEND),
)

time.sleep(3)

print("[3/3] Starting Cloudflare tunnel (logging to tunnel.log)...", flush=True)
tunnel_file = open(TUNNEL_LOG, "w", encoding="utf-8", buffering=1)

tunnel_proc = subprocess.Popen(
    [str(CLOUDFLARED), "tunnel", "--url", "http://127.0.0.1:5173"],
    stderr=tunnel_file,
    stdout=tunnel_file,
)

url = ""
start_time = time.time()
while time.time() - start_time < 30:
    time.sleep(1)
    if TUNNEL_LOG.exists():
        content = TUNNEL_LOG.read_text(encoding="utf-8", errors="ignore")
        match = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", content)
        if match:
            url = match.group(0)
            print(f"LIVE_URL: {url}", flush=True)
            break

print(f"Tunnel established! Ready at {url}", flush=True)

try:
    while True:
        if backend_proc.poll() is not None:
            backend_proc = subprocess.Popen(
                [str(PYTHON_EXE), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
                cwd=str(BACKEND),
                env=env,
            )
        if frontend_proc.poll() is not None:
            frontend_proc = subprocess.Popen(
                ["npm.cmd", "run", "dev"],
                cwd=str(FRONTEND),
            )
        if tunnel_proc.poll() is not None:
            tunnel_proc = subprocess.Popen(
                [str(CLOUDFLARED), "tunnel", "--url", "http://127.0.0.1:5173"],
                stderr=tunnel_file,
                stdout=tunnel_file,
            )
        time.sleep(5)
except KeyboardInterrupt:
    backend_proc.terminate()
    frontend_proc.terminate()
    tunnel_proc.terminate()
    tunnel_file.close()
