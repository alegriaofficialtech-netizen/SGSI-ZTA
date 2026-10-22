"""Operate only the native Compose project on the user's designated lab host."""

import argparse
import io
import shlex
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = "elcra@192.168.1.36"
REMOTE = "/home/elcra/sgsi-zta-native-app"
SSH = [
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
    HOST,
]


def remote(command: str, data: bytes | None = None) -> None:
    result = subprocess.run([*SSH, command], input=data, check=False)
    if result.returncode:
        raise SystemExit(result.returncode)


def discover() -> None:
    global REMOTE
    result = subprocess.run(
        [
            *SSH,
            "env -u DOCKER_HOST -u DOCKER_CONTEXT docker --context default inspect --format '{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}' sgsi-zta-native-backend-1",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    path = result.stdout.strip()
    if not path.startswith("/") or "\n" in path or path == "/":
        raise SystemExit("Could not detect a valid existing native Compose directory")
    REMOTE = path
    print("Existing native Compose directory detected: " + REMOTE)


def sync() -> None:
    package = io.BytesIO()
    excluded = {
        "node_modules",
        ".venv",
        "dist",
        "coverage",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        "evidence",
        ".private",
    }
    with tarfile.open(fileobj=package, mode="w:gz") as archive:
        for path in sorted(ROOT.rglob("*")):
            relative = path.relative_to(ROOT)
            if (
                path.is_file()
                and not (excluded & set(relative.parts))
                and path.suffix != ".db"
                and (not path.name.startswith(".env") or path.name == ".env.example")
            ):
                archive.add(path, arcname=relative.as_posix(), recursive=False)
    # Fixed directory and generated relative regular-file archive; no delete or pruning.
    remote(
        f"umask 077; mkdir -p {shlex.quote(REMOTE)} && tar -xzf - -C {shlex.quote(REMOTE)}"
        f" && cd {shlex.quote(REMOTE)} && if [ ! -f .env ]; then python3 scripts/init_env.py; fi"
        " && python3 scripts/upgrade_env.py",
        package.getvalue(),
    )
    print(f"Native source synced to {REMOTE}. Legacy project untouched.")


def compose(args: list[str]) -> None:
    command = [
        "env",
        "-u",
        "DOCKER_HOST",
        "-u",
        "DOCKER_CONTEXT",
        "docker",
        "--context",
        "default",
        "compose",
        "--project-name",
        "sgsi-zta-native",
        *args,
    ]
    remote(f"cd {shlex.quote(REMOTE)} && " + shlex.join(command))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=[
            "sync",
            "validate",
            "build",
            "up",
            "status",
            "test",
            "smoke",
            "logs",
            "mfa-initial",
            "mfa-persistence",
            "demo-up",
            "demo-down",
            "demo-status",
            "demo-urls",
            "mfa-public",
            "scan",
            "assets-initial",
            "assets-persistence",
            "assets-public",
            "exposure",
            "risks-initial",
            "risks-persistence",
            "risks-public",
        ],
    )
    action = parser.parse_args().action
    discover()
    if action == "sync":
        sync()
    elif action == "validate":
        compose(["config", "--quiet"])
    elif action == "build":
        compose(["build", "backend", "frontend"])
    elif action == "up":
        compose(["up", "-d", "--wait", "postgres", "backend", "frontend"])
    elif action == "test":
        compose(["--profile", "test", "run", "--rm", "backend-tests"])
    elif action == "smoke":
        compose(["exec", "-T", "backend", "python", "-m", "app.smoke"])
    elif action == "status":
        compose(["ps"])
    elif action == "logs":
        compose(["logs", "--tail", "60", "backend", "frontend"])
    elif action.startswith("demo-"):
        remote(
            f"cd {shlex.quote(REMOTE)} && python3 scripts/demo.py {shlex.quote(action.removeprefix('demo-'))}"
        )
    elif action in {"mfa-initial", "mfa-persistence", "mfa-public"}:
        docker = "env -u DOCKER_HOST -u DOCKER_CONTEXT docker --context default"
        base = docker + " compose --project-name sgsi-zta-native"
        if action == "mfa-persistence":
            compose(["down"])
            compose(["up", "-d", "--wait", "postgres", "backend", "frontend"])
        phase = action.removeprefix("mfa-")
        command = "python -m app.mfa_smoke --phase " + phase
        if phase == "public":
            command = "python -m app.smoke"
        output = "evidence/run-m2-server/" + phase + ".json"
        remote(
            f"cd {shlex.quote(REMOTE)} && umask 077 && mkdir -p evidence/run-m2-server .private && "
            + base
            + " exec -T backend "
            + command
            + " > "
            + output
            + " && cat "
            + output
        )
        if phase == "initial":
            remote(
                f"cd {shlex.quote(REMOTE)} && "
                + "if [ ! -f .private/m2-demo-recovery.enc ]; then "
                + base
                + " exec -T backend cat /tmp/m2-demo-recovery.enc > .private/m2-demo-recovery.enc && chmod 600 .private/m2-demo-recovery.enc; fi"
            )
        if phase == "persistence":
            remote(
                f"cd {shlex.quote(REMOTE)} && cp {output} evidence/m2-private-acceptance.json"
            )
    elif action.startswith("assets-"):
        phase = action.removeprefix("assets-")
        if phase == "persistence":
            compose(["down"])
            compose(["up", "-d", "--wait", "postgres", "backend", "frontend"])
        output = "evidence/run-m3-server/" + phase + ".json"
        remote(
            f"cd {shlex.quote(REMOTE)} && umask 077 && mkdir -p evidence/run-m3-server && "
            "env -u DOCKER_HOST -u DOCKER_CONTEXT docker --context default compose "
            "--project-name sgsi-zta-native exec -T backend python -m app.assets.acceptance --phase "
            + phase
            + " > "
            + output
            + " && cat "
            + output
        )
        if phase == "persistence":
            remote(
                f"cd {shlex.quote(REMOTE)} && cp {output} evidence/m3-private-acceptance.json"
            )
    elif action.startswith("risks-"):
        phase = action.removeprefix("risks-")
        if phase == "persistence":
            compose(["down"])
            compose(["up", "-d", "--wait", "postgres", "backend", "frontend"])
        output = "evidence/run-m4-server/" + phase + ".json"
        remote(
            f"cd {shlex.quote(REMOTE)} && umask 077 && mkdir -p evidence/run-m4-server && "
            "env -u DOCKER_HOST -u DOCKER_CONTEXT docker --context default compose "
            "--project-name sgsi-zta-native exec -T backend python -m app.risks.acceptance --phase "
            + phase + " > " + output + " && cat " + output
        )
        if phase == "persistence":
            remote(f"cd {shlex.quote(REMOTE)} && cp {output} evidence/m4-private-acceptance.json")
    elif action == "exposure":
        remote(f"cd {shlex.quote(REMOTE)} && python3 scripts/exposure.py")
    elif action == "scan":
        remote(f"cd {shlex.quote(REMOTE)} && python3 scripts/secret_scan.py --database")
