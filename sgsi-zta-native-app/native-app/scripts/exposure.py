"""Run on the native host; emit selected, non-secret Docker exposure evidence."""

import json
import os
import re
import subprocess
from pathlib import Path

environment = dict(os.environ)
environment.pop("DOCKER_HOST", None)
environment.pop("DOCKER_CONTEXT", None)
docker = ["docker", "--context", "default"]


def inspect(target):
    return json.loads(
        subprocess.run(
            [*docker, "inspect", target],
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )[0]


def main():
    report = {"status": "PASS", "services": {}}
    for service in ("frontend", "backend", "postgres"):
        container = inspect("sgsi-zta-native-" + service + "-1")
        bindings = container["HostConfig"].get("PortBindings") or {}
        published = [item for values in bindings.values() for item in (values or [])]
        health = container["State"].get("Health", {}).get("Status")
        assert health == "healthy", "Native service is not healthy"
        if service == "frontend":
            assert published and all(
                item["HostIp"] == "127.0.0.1" for item in published
            )
        else:
            assert not published, "Backend or PostgreSQL published a host port"
        report["services"][service] = {"health": health, "published_ports": published}
    network = inspect("sgsi-zta-native_database")
    assert network["Internal"], "Database network is not internal"
    report["database_network_internal"] = True
    listeners = subprocess.run(
        ["ss", "-lnt"], capture_output=True, text=True, check=True
    ).stdout
    sensitive = [
        port for port in (5432, 2375, 2376) if re.search(rf":{port}\s", listeners)
    ]
    assert not sensitive, "PostgreSQL or Docker TCP host listener found"
    report["postgres_5432_host_listener"] = False
    report["docker_tcp_host_listener"] = False
    report["postgresql"] = "PRIVATE"
    report["scope"] = (
        "Native Docker bindings and Linux host listeners; HTTP Quick Tunnel only"
    )
    root = Path(__file__).resolve().parents[1]
    destination = root / "evidence/run-m3-server/exposure.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
