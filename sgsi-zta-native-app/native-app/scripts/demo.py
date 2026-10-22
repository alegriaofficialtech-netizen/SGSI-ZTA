"""Run on the lab host. Publish/stop only the native temporary Quick Tunnel."""

import argparse
import json
import os
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / ".env.demo"
URL_PATTERN = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def compose(args, *, demo=True, capture=False):
    command = [
        "docker",
        "--context",
        "default",
        "compose",
        "--project-name",
        "sgsi-zta-native",
        "--env-file",
        ".env",
    ]
    if demo:
        command += ["--env-file", ".env.demo"]
    command += ["-f", "docker-compose.yml"]
    if demo:
        command += ["-f", "docker-compose.demo.yml"]
    command += args
    environment = dict(os.environ)
    environment.pop("DOCKER_HOST", None)
    environment.pop("DOCKER_CONTEXT", None)
    return subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=capture,
        text=True,
    )


def write_environment(url=""):
    origins = ["http://localhost:8090", "http://127.0.0.1:8090"]
    hosts = ["localhost", "127.0.0.1", "backend", "testserver"]
    if url:
        if not URL_PATTERN.fullmatch(url):
            raise RuntimeError("Unexpected public hostname")
        origins.append(url)
        hosts.append(url.removeprefix("https://"))
    ENV.write_text(
        "# Public hostname only; private encryption and DB keys stay in .env\n"
        + "DEMO_ALLOWED_ORIGINS="
        + json.dumps(origins, separators=(",", ":"))
        + "\n"
        + "DEMO_ALLOWED_HOSTS="
        + json.dumps(hosts, separators=(",", ":"))
        + "\n"
        + "DEMO_URL="
        + url
        + "\n",
        encoding="utf-8",
    )
    ENV.chmod(0o600)


def public_url():
    if not ENV.exists():
        return ""
    for line in ENV.read_text(encoding="utf-8").splitlines():
        if line.startswith("DEMO_URL="):
            return line.split("=", 1)[1]
    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["up", "down", "status", "urls"])
    action = parser.parse_args().action
    if action == "up":
        milestone = (
            "m4" if (ROOT / "backend/app/risks/routes.py").exists()
            else "m3" if (ROOT / "backend/app/assets/routes.py").exists() else "m2"
        )
        gate = ROOT / "evidence" / f"{milestone}-private-acceptance.json"
        if not gate.exists() or json.loads(gate.read_text())["status"] != "PASS":
            raise SystemExit(
                f"Private deployed {milestone.upper()} + persistence acceptance must PASS first"
            )
        if public_url():
            state = compose(
                ["ps", "--status", "running", "--services"], capture=True
            ).stdout.splitlines()
            if "cloudflared" in state:
                print("Temporary demo already running: " + public_url())
                return
        write_environment()
        compose(["rm", "-s", "-f", "cloudflared"])
        compose(["up", "-d", "--no-deps", "demo-gateway", "cloudflared"])
        deadline = time.monotonic() + 55
        url = ""
        while time.monotonic() < deadline:
            logs = compose(["logs", "--no-color", "cloudflared"], capture=True).stdout
            match = URL_PATTERN.search(logs)
            if match:
                url = match.group(0)
                break
            time.sleep(2)
        if not url:
            compose(["stop", "cloudflared", "demo-gateway"])
            raise SystemExit("Quick Tunnel did not return a hostname; demo stopped")
        write_environment(url)
        compose(["up", "-d", "--no-deps", "--wait", "backend"])
        print("Temporary public URL: " + url)
    elif action == "down":
        if ENV.exists():
            compose(["stop", "cloudflared", "demo-gateway"])
            compose(["rm", "-f", "cloudflared", "demo-gateway"])
        compose(["up", "-d", "--no-deps", "--wait", "backend"], demo=False)
        if ENV.exists():
            write_environment()
        print(
            "Demo stopped. PostgreSQL, volume, users and MFA preserved. Private HTTP settings restored."
        )
    elif action == "status":
        if ENV.exists():
            compose(["ps"])
        else:
            print("Demo has not been started")
    else:
        print(public_url() or "No active public URL")


if __name__ == "__main__":
    main()
