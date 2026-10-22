"""Run isolated UI QA with a temporary SQLite database and ephemeral credentials."""

import base64
import os
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
node = shutil.which("node")
if not node or not os.environ.get("NATIVE_PLAYWRIGHT_MODULE"):
    raise SystemExit(
        "Node and NATIVE_PLAYWRIGHT_MODULE (Playwright package path) required"
    )
milestone = os.environ.get("NATIVE_UI_MILESTONE", "m2")
if milestone not in {"m2", "m3"}:
    raise SystemExit("Expected m2 or m3 UI milestone")
output = root / "evidence" / f"run-{milestone}-ui-20261003"
output.mkdir(parents=True, exist_ok=True)
flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
processes = []
temporary_context = tempfile.TemporaryDirectory(prefix="sgsi-native-ui-")
with temporary_context as temporary:
    environment = {
        **os.environ,
        "DATABASE_URL": f"sqlite:///{Path(temporary) / 'ui.db'}",
        "JWT_SECRET": secrets.token_urlsafe(64),
        "MFA_ENCRYPTION_KEY": base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode(),
        "DEMO_PASSWORD": "Visual!Aa9-" + secrets.token_urlsafe(24),
        "COOKIE_SECURE": "false",
        "NATIVE_UI_OUTPUT": str(output),
        "ALLOWED_ORIGINS": '["http://127.0.0.1:5173"]',
    }
    environment["NATIVE_UI_PASSWORD"] = environment["DEMO_PASSWORD"]
    python = (
        str(root / "backend/.venv/Scripts/python.exe")
        if os.name == "nt"
        else str(root / "backend/.venv/bin/python")
    )
    environment["NATIVE_UI_PYTHON"] = str(python)
    with (output / "runtime.log").open("w", encoding="utf-8") as log:
        try:
            subprocess.run(
                [python, "-m", "alembic", "upgrade", "head"],
                cwd=root / "backend",
                env=environment,
                stdout=log,
                stderr=log,
                check=True,
            )
            subprocess.run(
                [python, "-m", "app.seed"],
                cwd=root / "backend",
                env=environment,
                stdout=log,
                stderr=log,
                check=True,
            )
            processes.append(
                subprocess.Popen(
                    [
                        python,
                        "-m",
                        "uvicorn",
                        "app.main:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        "8000",
                        "--no-access-log",
                    ],
                    cwd=root / "backend",
                    env=environment,
                    stdout=log,
                    stderr=log,
                    creationflags=flags,
                )
            )
            processes.append(
                subprocess.Popen(
                    [
                        node,
                        str(root / "frontend/node_modules/vite/bin/vite.js"),
                        "--host",
                        "127.0.0.1",
                        "--port",
                        "5173",
                        "--strictPort",
                    ],
                    cwd=root / "frontend",
                    env=environment,
                    stdout=log,
                    stderr=log,
                    creationflags=flags,
                )
            )
            for port, path in [(8000, "/api/v1/health"), (5173, "/login")]:
                for _ in range(60):
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}{path}", timeout=1
                        ):
                            break
                    except (urllib.error.URLError, TimeoutError):
                        if any(process.poll() is not None for process in processes):
                            raise RuntimeError(
                                "UI test runtime exited; see private runtime.log"
                            ) from None
                        time.sleep(0.5)
                else:
                    raise RuntimeError("UI runtime startup timed out")
            subprocess.run(
                [
                    node,
                    str(
                        root
                        / (
                            "scripts/assets_ui.cjs"
                            if milestone == "m3"
                            else "scripts/ui_smoke.cjs"
                        )
                    ),
                ],
                cwd=root,
                env=environment,
                check=True,
                creationflags=flags,
            )
        finally:
            for process in reversed(processes):
                if os.name == "nt" and process.poll() is None:
                    # Windows venv launchers can spawn another Python process.
                    # Kill only this recorded child tree, never a process by name.
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdout=log,
                        stderr=log,
                        check=False,
                        creationflags=flags,
                    )
                elif process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            # Windows can release a killed SQLite handle shortly after the child exits.
            generated_temp = Path(temporary).resolve()
            if generated_temp.parent != Path(
                tempfile.gettempdir()
            ).resolve() or not generated_temp.name.startswith("sgsi-native-ui-"):
                raise RuntimeError(
                    "Unexpected UI temporary directory; refusing cleanup"
                )
            for attempt in range(10):
                try:
                    temporary_context.cleanup()
                    break
                except PermissionError:
                    if attempt == 9:
                        raise
                    time.sleep(0.2)
