"""Tests for M6.5 Native File Integrity Monitoring (FIM).

Validates path traversal blocking, symlink defenses, streaming SHA-256 hashing,
principal lifecycle workflow (scan, change, alert, dedup, restore), missing file
detection, no content leakage, RBAC / Zero Trust PEP enforcement, and metrics.
"""
from pathlib import Path

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.models.identity import AuditLog
from app.models.monitoring import (
    Alert,
    AlertHistory,
    FimTarget,
    MonitoringEvent,
    MonitoringSource,
)
from app.models.policies import PolicyDecision
from app.monitoring.fim import (
    FimFileSizeExceededError,
    FimInvalidTargetError,
    FimPathSecurityError,
    compute_file_sha256,
    resolve_safe_fim_path,
)
from app.monitoring.types import EventType, Severity
from app.tests.conftest import login

FIM_BASE_URL = "/api/v1/monitoring/fim"


def get_data_root() -> Path:
    return Path(get_settings().get_monitoring_data_root()).resolve()


@pytest.fixture(autouse=True)
def setup_test_monitoring_root(tmp_path, monkeypatch):
    """Set up an isolated writable sandbox for FIM tests, compatible with read-only containers."""
    data_dir = tmp_path / "monitoring-data"
    data_dir.mkdir(parents=True, exist_ok=True)

    default_root = Path(get_settings().get_monitoring_data_root()).resolve()
    if default_root.exists() and default_root.is_dir():
        for item in default_root.iterdir():
            if item.is_file():
                (data_dir / item.name).write_bytes(item.read_bytes())

    monkeypatch.setenv("MONITORING_DATA_ROOT", str(data_dir.resolve()))
    get_settings.cache_clear()

    from app.monitoring.seed import seed_monitoring_fim
    with SessionLocal() as db:
        seed_monitoring_fim(db)

    yield data_dir
    get_settings.cache_clear()


# =========================================================================
# 1. Path Security & Symlink Tests
# =========================================================================


def test_fim_path_security_attacks(tmp_path):
    root = tmp_path / "sandbox"
    root.mkdir()
    valid_file = root / "valid.json"
    valid_file.write_text('{"status": "ok"}', encoding="utf-8")

    sub_dir = root / "subdir"
    sub_dir.mkdir()

    # Valid relative paths
    assert resolve_safe_fim_path("valid.json", data_root=root) == valid_file.resolve()

    # Traversal attacks
    traversal_attacks = [
        "../secret.txt",
        "../../etc/passwd",
        "..\\secret.txt",
        "subdir/../../outside.txt",
        "%2e%2e%2fsecret.json",
        "%2e%2e/outside.json",
        "valid.json\0attack",
        "valid.json;rm -rf",
        "*.json",
        "valid?.json",
        "valid[1].json",
    ]
    for attack in traversal_attacks:
        with pytest.raises(FimPathSecurityError):
            resolve_safe_fim_path(attack, data_root=root)

    # Absolute, Drive, and UNC paths
    abs_attacks = [
        "/etc/passwd",
        "\\Windows\\system32",
        "C:\\Windows\\system.ini",
        "D:file.txt",
        "\\\\server\\share\\data.json",
        "//server/share/data.json",
    ]
    for attack in abs_attacks:
        with pytest.raises(FimPathSecurityError):
            resolve_safe_fim_path(attack, data_root=root)

    # Directory target rejected
    with pytest.raises(FimInvalidTargetError):
        resolve_safe_fim_path("subdir", data_root=root)

    # Root directory itself rejected
    with pytest.raises(FimPathSecurityError):
        resolve_safe_fim_path(".", data_root=root)


def test_fim_symlink_rejection(tmp_path):
    root = tmp_path / "sandbox"
    root.mkdir()
    outside_file = tmp_path / "outside.secret"
    outside_file.write_text("CONFIDENTIAL", encoding="utf-8")

    symlink_target = root / "symlink_escape.json"
    try:
        symlink_target.symlink_to(outside_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted in this OS/environment")

    with pytest.raises(FimPathSecurityError):
        resolve_safe_fim_path("symlink_escape.json", data_root=root)


# =========================================================================
# 2. Streaming SHA-256 Hashing Tests
# =========================================================================


def test_fim_streaming_hashing(tmp_path):
    test_file = tmp_path / "hash_test.json"
    content = b'{"data": "synthetic-test-content-12345"}'
    test_file.write_bytes(content)

    import hashlib

    expected_hash = hashlib.sha256(content).hexdigest().lower()
    computed_hash = compute_file_sha256(test_file)

    assert computed_hash == expected_hash
    assert len(computed_hash) == 64
    assert computed_hash == computed_hash.lower()

    # File size limit enforcement
    with pytest.raises(FimFileSizeExceededError):
        compute_file_sha256(test_file, max_size=10)


# =========================================================================
# 3. Principal Workflow: Scan -> Change -> Alert -> Dedup -> Restore
# =========================================================================


def test_fim_principal_workflow(client):
    """Test required M6.5 principal workflow."""
    login(client, "admin.demo")
    root = get_data_root()

    # 1. Target enabled (use test file in data root)
    test_file = root / "principal-workflow-demo.json"
    initial_content = '{"synthetic": true, "version": 1, "field": "initial"}'
    test_file.write_text(initial_content, encoding="utf-8")

    try:
        # Create target
        create_res = client.post(
            f"{FIM_BASE_URL}/targets",
            json={
                "target_code": "FIM-TEST-PRINCIPAL",
                "relative_path": "principal-workflow-demo.json",
                "enabled": True,
            },
        )
        assert create_res.status_code == 201, create_res.text
        target_id = create_res.json()["id"]
        baseline_hash = create_res.json()["baseline_sha256"]
        assert len(baseline_hash) == 64

        # 2. Create / Re-baseline
        baseline_res = client.post(f"{FIM_BASE_URL}/targets/{target_id}/baseline")
        assert baseline_res.status_code == 200
        assert baseline_res.json()["baseline_sha256"] == baseline_hash

        # 3. Scan -> NO CHANGE
        scan_1 = client.post(f"{FIM_BASE_URL}/targets/{target_id}/scan")
        assert scan_1.status_code == 200
        assert scan_1.json()["status"] == "NO_CHANGE"
        assert scan_1.json()["current_sha256"] == baseline_hash

        # 4. Modify synthetic file
        modified_content = '{"synthetic": true, "version": 2, "field": "tampered"}'
        test_file.write_text(modified_content, encoding="utf-8")

        # 5. Scan -> CHANGE DETECTED
        scan_2 = client.post(f"{FIM_BASE_URL}/targets/{target_id}/scan")
        assert scan_2.status_code == 200
        data_2 = scan_2.json()
        assert data_2["status"] == "CHANGED"
        assert data_2["current_sha256"] != baseline_hash
        assert data_2["event_id"] is not None
        assert data_2["alert_id"] is not None
        alert_id_1 = data_2["alert_id"]

        with SessionLocal() as db:
            # Verify MonitoringEvent created
            event = db.get(MonitoringEvent, data_2["event_id"])
            assert event is not None
            assert event.event_type == EventType.FILE_INTEGRITY_CHANGE
            assert event.severity in {Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL}
            assert event.payload_json["target_code"] == "FIM-TEST-PRINCIPAL"
            assert event.payload_json["reason"] == "HASH_MISMATCH"

            # Verify baseline was NOT modified
            target_in_db = db.get(FimTarget, target_id)
            assert target_in_db.baseline_sha256 == baseline_hash
            assert target_in_db.last_sha256 == data_2["current_sha256"]

            # Verify alert
            alert = db.get(Alert, alert_id_1)
            assert alert is not None
            assert alert.occurrence_count == 1

        # 6. Scan again -> DEDUPLICATION
        scan_3 = client.post(f"{FIM_BASE_URL}/targets/{target_id}/scan")
        assert scan_3.status_code == 200
        data_3 = scan_3.json()
        assert data_3["status"] == "CHANGED"
        assert data_3["alert_id"] == alert_id_1

        with SessionLocal() as db:
            alert = db.get(Alert, alert_id_1)
            assert alert.occurrence_count == 2
            # Verify ALERT_DEDUPLICATED in history
            histories = list(
                db.scalars(
                    select(AlertHistory).where(
                        AlertHistory.alert_id == alert_id_1,
                        AlertHistory.action == "ALERT_DEDUPLICATED",
                    )
                )
            )
            assert len(histories) >= 1

        # 7. Restore file to original content
        test_file.write_text(initial_content, encoding="utf-8")

        # 8. Scan -> NO CHANGE
        scan_4 = client.post(f"{FIM_BASE_URL}/targets/{target_id}/scan")
        assert scan_4.status_code == 200
        assert scan_4.json()["status"] == "NO_CHANGE"
        assert scan_4.json()["current_sha256"] == baseline_hash

        # 9. Verify previous alerts and history are intact
        with SessionLocal() as db:
            alert = db.get(Alert, alert_id_1)
            assert alert is not None
            assert alert.occurrence_count == 2
    finally:
        if test_file.exists():
            test_file.unlink()


# =========================================================================
# 4. File Missing and File Restored Tests
# =========================================================================


def test_fim_file_disappears_and_restores(client):
    login(client, "admin.demo")
    root = get_data_root()

    test_file = root / "disappearing-file.json"
    original_content = '{"sample": "synthetic"}'
    test_file.write_text(original_content, encoding="utf-8")

    try:
        # Create target
        res = client.post(
            f"{FIM_BASE_URL}/targets",
            json={
                "target_code": "FIM-DISAPPEARING",
                "relative_path": "disappearing-file.json",
                "enabled": True,
            },
        )
        assert res.status_code == 201
        target_id = res.json()["id"]

        # Delete file
        test_file.unlink()

        # Scan -> Must return MISSING, NOT 500
        scan_missing = client.post(f"{FIM_BASE_URL}/targets/{target_id}/scan")
        assert scan_missing.status_code == 200
        missing_data = scan_missing.json()
        assert missing_data["status"] == "MISSING"
        assert missing_data["current_sha256"] is None
        assert missing_data["event_id"] is not None

        with SessionLocal() as db:
            event = db.get(MonitoringEvent, missing_data["event_id"])
            assert event is not None
            assert event.payload_json["reason"] == "FILE_MISSING"

        # Restore file
        test_file.write_text(original_content, encoding="utf-8")

        # Scan -> returns NO_CHANGE
        scan_restored = client.post(f"{FIM_BASE_URL}/targets/{target_id}/scan")
        assert scan_restored.status_code == 200
        assert scan_restored.json()["status"] == "NO_CHANGE"
    finally:
        if test_file.exists():
            test_file.unlink()


# =========================================================================
# 5. No Content Leak Verification
# =========================================================================


def test_fim_no_content_leak(client):
    login(client, "admin.demo")
    root = get_data_root()

    sensitive_content = (
        '{"secret_password": "super-secret-password-12345", '
        '"patient_ssn": "000-00-0000", '
        '"medical_diagnosis": "PRIVATE_CARDIAC_CONDITION"}'
    )
    test_file = root / "sensitive-markers.json"
    test_file.write_text(sensitive_content, encoding="utf-8")

    try:
        create_res = client.post(
            f"{FIM_BASE_URL}/targets",
            json={
                "target_code": "FIM-NO-LEAK",
                "relative_path": "sensitive-markers.json",
                "enabled": True,
            },
        )
        assert create_res.status_code == 201
        target_id = create_res.json()["id"]

        # Modify file with altered sensitive markers
        test_file.write_text(sensitive_content + '{"tampered": true}', encoding="utf-8")

        scan_res = client.post(f"{FIM_BASE_URL}/targets/{target_id}/scan")
        assert scan_res.status_code == 200
        event_id = scan_res.json()["event_id"]

        with SessionLocal() as db:
            event = db.get(MonitoringEvent, event_id)
            assert event is not None

            # Verify no sensitive keywords exist in title, message, or payload
            sensitive_words = [
                "super-secret-password",
                "000-00-0000",
                "PRIVATE_CARDIAC_CONDITION",
                "secret_password",
                "patient_ssn",
                "medical_diagnosis",
            ]
            for word in sensitive_words:
                assert word not in event.title
                assert word not in event.message
                assert word not in str(event.payload_json)
    finally:
        if test_file.exists():
            test_file.unlink()


# =========================================================================
# 6. RBAC / Zero Trust PEP Tests
# =========================================================================


def test_fim_rbac_and_pep(client):
    # Anonymous -> 401
    assert client.get(f"{FIM_BASE_URL}/targets").status_code == 401

    # Clinical role: Medico -> 403 on all FIM endpoints
    login(client, "medico.demo")
    assert client.get(f"{FIM_BASE_URL}/targets").status_code == 403
    assert client.post(f"{FIM_BASE_URL}/scan").status_code == 403
    assert client.get("/api/v1/monitoring/metrics/fim").status_code == 403

    # Clinical role: Admision -> 403
    login(client, "admision.demo")
    assert client.get(f"{FIM_BASE_URL}/targets").status_code == 403

    # Auditor -> Read-only (200 on GET, 403 on scan/create/baseline/patch)
    login(client, "auditor.demo")
    res_list = client.get(f"{FIM_BASE_URL}/targets")
    assert res_list.status_code == 200
    assert client.get("/api/v1/monitoring/metrics/fim").status_code == 200

    assert client.post(f"{FIM_BASE_URL}/scan").status_code == 403
    assert (
        client.post(
            f"{FIM_BASE_URL}/targets",
            json={"target_code": "FIM-DENY", "relative_path": "patient-demo.json"},
        ).status_code
        == 403
    )

    # Admin-TI -> Full control
    login(client, "admin.demo")
    assert client.get(f"{FIM_BASE_URL}/targets").status_code == 200
    assert client.post(f"{FIM_BASE_URL}/scan").status_code == 200

    # Verify Zero Trust Policy Decisions recorded
    with SessionLocal() as db:
        decisions = list(
            db.scalars(
                select(PolicyDecision).where(
                    PolicyDecision.resource == "monitoring-fim"
                )
            )
        )
        assert len(decisions) >= 4


# =========================================================================
# 7. Target Creation Schemas & Constraints
# =========================================================================


def test_fim_target_creation_constraints(client):
    login(client, "admin.demo")

    # Forbidden fields rejected with extra='forbid'
    forbidden_payload = {
        "target_code": "FIM-EXTRA",
        "relative_path": "patient-demo.json",
        "baseline_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    }
    assert client.post(f"{FIM_BASE_URL}/targets", json=forbidden_payload).status_code == 422

    # Non-existent file rejected
    non_existent = {
        "target_code": "FIM-NON-EXISTENT",
        "relative_path": "file-that-does-not-exist.json",
    }
    assert client.post(f"{FIM_BASE_URL}/targets", json=non_existent).status_code == 422

    # Duplicate target code rejected
    dup_1 = {
        "target_code": "FIM-DUP",
        "relative_path": "patient-demo.json",
    }
    assert client.post(f"{FIM_BASE_URL}/targets", json=dup_1).status_code == 201
    assert client.post(f"{FIM_BASE_URL}/targets", json=dup_1).status_code == 409


# =========================================================================
# 8. Re-baseline Operation
# =========================================================================


def test_fim_rebaseline(client):
    login(client, "admin.demo")
    root = get_data_root()

    test_file = root / "rebaseline-demo.json"
    test_file.write_text('{"v": 1}', encoding="utf-8")

    try:
        create_res = client.post(
            f"{FIM_BASE_URL}/targets",
            json={
                "target_code": "FIM-REBASELINE",
                "relative_path": "rebaseline-demo.json",
            },
        )
        target_id = create_res.json()["id"]
        old_hash = create_res.json()["baseline_sha256"]

        # Modify file
        test_file.write_text('{"v": 2}', encoding="utf-8")
        scan_before = client.post(f"{FIM_BASE_URL}/targets/{target_id}/scan")
        assert scan_before.json()["status"] == "CHANGED"

        # Rebaseline
        rebase_res = client.post(f"{FIM_BASE_URL}/targets/{target_id}/baseline")
        assert rebase_res.status_code == 200
        new_hash = rebase_res.json()["baseline_sha256"]
        assert new_hash != old_hash

        # Scan after rebaseline -> NO_CHANGE
        scan_after = client.post(f"{FIM_BASE_URL}/targets/{target_id}/scan")
        assert scan_after.json()["status"] == "NO_CHANGE"

        # Verify AuditLog recorded
        with SessionLocal() as db:
            audit_entry = db.scalar(
                select(AuditLog).where(
                    AuditLog.action == "FIM_BASELINE_CREATED",
                    AuditLog.resource == f"fim-target:{target_id}",
                )
            )
            assert audit_entry is not None
    finally:
        if test_file.exists():
            test_file.unlink()


# =========================================================================
# 9. Internal Source Protection
# =========================================================================


def test_internal_fim_source_protection(client):
    login(client, "admin.demo")

    # Cannot create external source with SRC-NATIVE-FIM
    create_src_res = client.post(
        "/api/v1/monitoring/sources",
        json={
            "source_code": "SRC-NATIVE-FIM",
            "name": "Spoofed FIM",
            "source_type": "FIM",
        },
    )
    assert create_src_res.status_code in (400, 409, 422)

    # Cannot rotate key for internal source
    with SessionLocal() as db:
        internal_src = db.scalar(
            select(MonitoringSource).where(
                MonitoringSource.source_code == "SRC-NATIVE-FIM"
            )
        )
        assert internal_src is not None
        src_id = internal_src.id

    rotate_res = client.post(f"/api/v1/monitoring/sources/{src_id}/rotate-key")
    assert rotate_res.status_code == 400


# =========================================================================
# 10. Metrics Foundation
# =========================================================================


def test_fim_metrics(client):
    login(client, "admin.demo")

    res = client.get("/api/v1/monitoring/metrics/fim")
    assert res.status_code == 200
    data = res.json()
    assert "fim_targets_enabled" in data
    assert "fim_scans_24h" in data
    assert "fim_changes_24h" in data
    assert data["fim_targets_enabled"] >= 1


def test_fim_global_scan(client):
    login(client, "admin.demo")

    scan_res = client.post(f"{FIM_BASE_URL}/scan")
    assert scan_res.status_code == 200
    data = scan_res.json()
    assert "total_targets" in data
    assert "scanned" in data
    assert "unchanged" in data
    assert "changed" in data
    assert "missing" in data
    assert "errors" in data
    assert "results" in data
    assert data["scanned"] == data["total_targets"]
    assert data["total_targets"] >= 3
    assert len(data["results"]) == data["total_targets"]
