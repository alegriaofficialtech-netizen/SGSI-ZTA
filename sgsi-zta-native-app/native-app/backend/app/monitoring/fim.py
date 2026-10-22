"""Native File Integrity Monitoring (FIM) engine for SGSI-ZTA.

Academic, deterministic file integrity verification operating strictly within
the designated synthetic MONITORING_DATA_ROOT. Enforces absolute path containment,
prohibits symlink escapes, computes streaming SHA-256 hashes, feeds detected
changes to AlertEngine, and records immutable AuditLog operations.
"""
import hashlib
import os
import urllib.parse
from pathlib import Path, PurePath
from uuid import UUID

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import now_utc
from app.models import Asset, User
from app.models.monitoring import (
    FimTarget,
    MonitoringEvent,
    MonitoringSource,
)
from app.monitoring.engine import AlertEngine
from app.monitoring.schemas import (
    FimGlobalScanResponse,
    FimScanResult,
    FimTargetCreate,
    FimTargetUpdate,
)
from app.monitoring.security import compute_event_fingerprint
from app.monitoring.types import EventType, Severity, SourceType
from app.services import audit

MAX_FIM_FILE_SIZE = 10 * 1024 * 1024  # 10 MB maximum file size
CHUNK_SIZE = 64 * 1024  # 64 KB read buffer
INTERNAL_FIM_SOURCE_CODE = "SRC-NATIVE-FIM"
FORBIDDEN_CHARS = {"*", "?", "[", "]", "{", "}", "$", "`", ";", "&", "|", "<", ">"}


class FimError(Exception):
    """Base class for FIM errors."""


class FimPathSecurityError(FimError):
    """Raised when a candidate path violates security or sandbox boundaries."""


class FimInvalidTargetError(FimError):
    """Raised when a candidate target is not a valid regular file."""


class FimFileSizeExceededError(FimError):
    """Raised when a file exceeds maximum supported streaming size."""


def resolve_safe_fim_path(
    relative_path: str,
    data_root: Path | str | None = None,
) -> Path:
    """Resolve and validate a relative path strictly within MONITORING_DATA_ROOT.

    Enforces:
    - Rejection of empty/whitespace paths.
    - Rejection of null bytes (\\0).
    - Rejection of URL-encoded traversal sequences (%2e%2e, %2f, %5c).
    - Rejection of directory traversal components (..).
    - Rejection of absolute, Windows drive (C:), or UNC (\\\\) paths.
    - Rejection of glob or shell metacharacters (*, ?, [, ]).
    - Rejection of symbolic links anywhere in the path hierarchy.
    - Strict sandbox containment verification using Path.is_relative_to.
    - Rejection of target being the root directory itself.
    - When target exists: rejection of directories, sockets, devices, and fifos.
    """
    if not relative_path or not relative_path.strip():
        raise FimPathSecurityError("Target relative path cannot be empty.")

    # 1. Null byte check
    if "\0" in relative_path:
        raise FimPathSecurityError("Null bytes are strictly prohibited.")

    # 2. URL decoding traversal check
    unquoted = urllib.parse.unquote(relative_path)
    if unquoted != relative_path:
        if any(seq in unquoted for seq in ("..", "/", "\\", "\0", ":")):
            raise FimPathSecurityError("Encoded path traversal patterns are strictly prohibited.")

    # 3. Traversal patterns and glob characters
    if ".." in relative_path or ".." in unquoted:
        raise FimPathSecurityError("Path traversal ('..') is strictly prohibited.")

    if any(ch in relative_path for ch in FORBIDDEN_CHARS):
        raise FimPathSecurityError("Wildcard or shell patterns are strictly prohibited.")

    # 4. Absolute, Drive, or UNC check
    if ":" in relative_path:
        raise FimPathSecurityError("Drive letters and alternate data streams are prohibited.")

    if relative_path.startswith(("/", "\\")) or relative_path.startswith(("\\\\", "//")):
        raise FimPathSecurityError("Absolute or UNC paths are strictly prohibited.")

    if os.path.isabs(relative_path) or PurePath(relative_path).is_absolute():
        raise FimPathSecurityError("Absolute paths are strictly prohibited.")

    # 5. Resolve base root
    root_dir = Path(data_root or get_settings().get_monitoring_data_root()).resolve()
    if not root_dir.exists():
        root_dir.mkdir(parents=True, exist_ok=True)

    # 6. Build candidate path
    try:
        candidate = root_dir / PurePath(relative_path)
    except Exception as exc:
        raise FimPathSecurityError(f"Invalid path construction: {exc}") from exc

    # 7. Symlink check: verify candidate and all intermediate components
    # Prohibit any symlinks within the sandbox
    curr = candidate
    while curr != root_dir and curr != curr.parent:
        if curr.is_symlink():
            raise FimPathSecurityError("Symbolic links are strictly prohibited in FIM.")
        curr = curr.parent

    # 8. Strict resolution and containment check
    resolved = candidate.resolve()
    if resolved.is_symlink():
        raise FimPathSecurityError("Symbolic links are strictly prohibited in FIM.")

    try:
        if not resolved.is_relative_to(root_dir):
            raise FimPathSecurityError("Path escapes the monitoring data sandbox root.")
    except (AttributeError, ValueError):
        # Fallback for earlier pathlib implementations if needed
        try:
            resolved.relative_to(root_dir)
        except ValueError as exc:
            raise FimPathSecurityError("Path escapes the monitoring data sandbox root.") from exc

    if resolved == root_dir:
        raise FimPathSecurityError("The root directory itself cannot be a FIM target.")

    # 9. If file exists, ensure it is a regular file
    if resolved.exists():
        if resolved.is_dir():
            raise FimInvalidTargetError("Target is a directory; a regular file is required.")
        if not resolved.is_file():
            raise FimInvalidTargetError("Target is not a regular file (device, socket, or pipe).")

    return resolved


def compute_file_sha256(path: Path, max_size: int = MAX_FIM_FILE_SIZE) -> str:
    """Compute lowercase 64-hex SHA-256 hash using streaming chunks.

    Enforces maximum file size limit to prevent memory exhaustion or DoS.
    """
    if not path.is_file():
        raise FimInvalidTargetError(f"Cannot hash non-file: {path}")

    size = path.stat().st_size
    if size > max_size:
        raise FimFileSizeExceededError(
            f"File size ({size} bytes) exceeds maximum supported limit ({max_size} bytes)."
        )

    hasher = hashlib.sha256()
    bytes_read = 0
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_SIZE):
            bytes_read += len(chunk)
            if bytes_read > max_size:
                raise FimFileSizeExceededError("File size exceeded limit during streaming hash.")
            hasher.update(chunk)

    digest_val = hasher.hexdigest().lower()
    if len(digest_val) != 64:
        raise ValueError("Invalid SHA-256 digest length generated.")
    return digest_val


def derive_fim_severity(asset: Asset | None) -> Severity:
    """Derive event severity deterministically based on Asset criticality.

    Mapping:
    - CRITICAL -> Severity.CRITICAL
    - HIGH     -> Severity.HIGH
    - MEDIUM   -> Severity.MEDIUM
    - LOW      -> Severity.LOW
    - None     -> Severity.HIGH (conservative zero-trust default for unclassified files)
    """
    if not asset or not asset.criticality:
        return Severity.HIGH
    crit = str(asset.criticality).upper()
    if crit == "CRITICAL":
        return Severity.CRITICAL
    if crit == "HIGH":
        return Severity.HIGH
    if crit == "MEDIUM":
        return Severity.MEDIUM
    if crit == "LOW":
        return Severity.LOW
    return Severity.HIGH


def get_or_create_internal_fim_source(db: Session) -> MonitoringSource:
    """Retrieve or initialize the internal SRC-NATIVE-FIM monitoring source.

    This source is internal-only and rejected by external ingestion endpoints.
    """
    source = db.scalar(
        select(MonitoringSource).where(
            MonitoringSource.source_code == INTERNAL_FIM_SOURCE_CODE
        )
    )
    if not source:
        source = MonitoringSource(
            source_code=INTERNAL_FIM_SOURCE_CODE,
            name="Monitor Nativo de Integridad de Archivos (FIM)",
            source_type=SourceType.FIM,
            enabled=True,
            key_hash="INTERNAL_SYSTEM_SERVICE_KEY_UNUSABLE",
            last_seen_at=now_utc(),
        )
        db.add(source)
        db.flush()
    return source


class FimService:
    """Orchestrates FIM target management, baseline tracking, and scans."""

    @staticmethod
    def list_targets(db: Session, enabled_only: bool = False) -> list[FimTarget]:
        stmt = select(FimTarget).order_by(FimTarget.created_at.desc())
        if enabled_only:
            stmt = stmt.where(FimTarget.enabled.is_(True))
        return list(db.scalars(stmt))

    @staticmethod
    def get_target(db: Session, target_id: str | UUID) -> FimTarget:
        target = db.get(FimTarget, str(target_id))
        if not target:
            raise HTTPException(status_code=404, detail="FIM target not found.")
        return target

    @staticmethod
    def create_target(
        db: Session,
        request: Request,
        actor: User,
        body: FimTargetCreate,
    ) -> FimTarget:
        # 1. Check uniqueness of target_code
        existing = db.scalar(
            select(FimTarget).where(FimTarget.target_code == body.target_code)
        )
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"FIM target code '{body.target_code}' already exists.",
            )

        # 2. Check asset if specified
        asset: Asset | None = None
        if body.asset_id is not None:
            asset = db.get(Asset, body.asset_id)
            if not asset:
                raise HTTPException(
                    status_code=422,
                    detail=f"Asset ID {body.asset_id} does not exist.",
                )

        # 3. Path security validation
        try:
            resolved_path = resolve_safe_fim_path(body.relative_path)
        except FimPathSecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except FimInvalidTargetError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        # 4. Verify target file exists to establish initial baseline
        if not resolved_path.is_file():
            raise HTTPException(
                status_code=422,
                detail=f"Target file does not exist at monitored path: {body.relative_path}",
            )

        # 5. Compute initial SHA-256 hash
        try:
            initial_hash = compute_file_sha256(resolved_path)
        except FimFileSizeExceededError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(
                status_code=403, detail="Permission denied reading target file."
            ) from exc

        now = now_utc()
        target = FimTarget(
            target_code=body.target_code,
            relative_path=body.relative_path,
            asset_id=body.asset_id,
            baseline_sha256=initial_hash,
            last_sha256=initial_hash,
            enabled=body.enabled,
            last_checked_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(target)
        db.flush()

        audit.record(
            db,
            request,
            action="FIM_TARGET_CREATED",
            resource=f"fim-target:{target.id}",
            decision="ALLOW",
            user=actor,
            detail=f"code={target.target_code} path={target.relative_path} sha256={initial_hash}",
        )
        db.commit()
        db.refresh(target)
        return target

    @staticmethod
    def update_target(
        db: Session,
        request: Request,
        actor: User,
        target_id: str | UUID,
        body: FimTargetUpdate,
    ) -> FimTarget:
        target = FimService.get_target(db, target_id)

        if body.asset_id is not None:
            asset = db.get(Asset, body.asset_id)
            if not asset:
                raise HTTPException(
                    status_code=422,
                    detail=f"Asset ID {body.asset_id} does not exist.",
                )
            target.asset_id = body.asset_id

        if body.enabled is not None:
            target.enabled = body.enabled

        target.updated_at = now_utc()
        audit.record(
            db,
            request,
            action="FIM_TARGET_UPDATED",
            resource=f"fim-target:{target.id}",
            decision="ALLOW",
            user=actor,
            detail=f"code={target.target_code} enabled={target.enabled}",
        )
        db.commit()
        db.refresh(target)
        return target

    @staticmethod
    def create_baseline(
        db: Session,
        request: Request,
        actor: User,
        target_id: str | UUID,
    ) -> FimTarget:
        """Calculate and update the target's baseline SHA-256 hash (re-baseline)."""
        target = FimService.get_target(db, target_id)

        try:
            resolved_path = resolve_safe_fim_path(target.relative_path)
        except FimPathSecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except FimInvalidTargetError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        if not resolved_path.is_file():
            raise HTTPException(
                status_code=404,
                detail=f"Monitored file not found: {target.relative_path}",
            )

        try:
            current_hash = compute_file_sha256(resolved_path)
        except FimFileSizeExceededError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(
                status_code=403, detail="Permission denied reading target file."
            ) from exc

        now = now_utc()
        target.baseline_sha256 = current_hash
        target.last_sha256 = current_hash
        target.last_checked_at = now
        target.updated_at = now

        audit.record(
            db,
            request,
            action="FIM_BASELINE_CREATED",
            resource=f"fim-target:{target.id}",
            decision="ALLOW",
            user=actor,
            detail=f"code={target.target_code} baseline_sha256={current_hash}",
        )
        db.commit()
        db.refresh(target)
        return target

    @staticmethod
    def scan_target(
        db: Session,
        request: Request,
        actor: User,
        target_or_id: FimTarget | str | UUID,
    ) -> FimScanResult:
        """Scan a single FIM target.

        Detects file modification or disappearance, records MonitoringEvent
        without content leakage, processes event through AlertEngine, and audits.
        Preserves baseline_sha256 unchanged upon detected divergence.
        """
        if isinstance(target_or_id, FimTarget):
            target = target_or_id
        else:
            target = FimService.get_target(db, target_or_id)

        try:
            resolved_path = resolve_safe_fim_path(target.relative_path)
        except FimPathSecurityError as exc:
            return FimScanResult(
                target_id=target.id,
                target_code=target.target_code,
                relative_path=target.relative_path,
                status="ERROR",
                baseline_sha256=target.baseline_sha256,
                current_sha256=None,
                message=f"Path security violation: {exc}",
            )
        except FimInvalidTargetError as exc:
            return FimScanResult(
                target_id=target.id,
                target_code=target.target_code,
                relative_path=target.relative_path,
                status="ERROR",
                baseline_sha256=target.baseline_sha256,
                current_sha256=None,
                message=f"Invalid target: {exc}",
            )

        now = now_utc()

        # Handle missing file
        if not resolved_path.exists():
            return FimService._handle_change_detected(
                db=db,
                request=request,
                actor=actor,
                target=target,
                current_hash=None,
                reason="FILE_MISSING",
                status_code="MISSING",
                message=f"Monitored file disappeared: {target.relative_path}",
            )

        # Handle permission error or file size error
        try:
            current_hash = compute_file_sha256(resolved_path)
        except PermissionError:
            audit.record(
                db,
                request,
                action="FIM_SCAN_ERROR",
                resource=f"fim-target:{target.id}",
                decision="DENY",
                user=actor,
                detail=f"code={target.target_code} error=Permission denied",
            )
            db.commit()
            return FimScanResult(
                target_id=target.id,
                target_code=target.target_code,
                relative_path=target.relative_path,
                status="ERROR",
                baseline_sha256=target.baseline_sha256,
                current_sha256=None,
                message="Permission denied reading monitored target.",
            )
        except FimFileSizeExceededError as exc:
            audit.record(
                db,
                request,
                action="FIM_SCAN_ERROR",
                resource=f"fim-target:{target.id}",
                decision="DENY",
                user=actor,
                detail=f"code={target.target_code} error=File size exceeded",
            )
            db.commit()
            return FimScanResult(
                target_id=target.id,
                target_code=target.target_code,
                relative_path=target.relative_path,
                status="ERROR",
                baseline_sha256=target.baseline_sha256,
                current_sha256=None,
                message=str(exc),
            )

        # Check for change
        if current_hash == target.baseline_sha256:
            # NO CHANGE
            target.last_sha256 = current_hash
            target.last_checked_at = now
            target.updated_at = now

            audit.record(
                db,
                request,
                action="FIM_SCAN_EXECUTED",
                resource=f"fim-target:{target.id}",
                decision="ALLOW",
                user=actor,
                detail=f"code={target.target_code} status=NO_CHANGE sha256={current_hash}",
            )
            db.commit()
            return FimScanResult(
                target_id=target.id,
                target_code=target.target_code,
                relative_path=target.relative_path,
                status="NO_CHANGE",
                baseline_sha256=target.baseline_sha256,
                current_sha256=current_hash,
                message="File integrity verified; hash matches baseline.",
            )

        # CHANGE DETECTED
        return FimService._handle_change_detected(
            db=db,
            request=request,
            actor=actor,
            target=target,
            current_hash=current_hash,
            reason="HASH_MISMATCH",
            status_code="CHANGED",
            message=f"File integrity violation: hash mismatch on {target.target_code}.",
        )

    @staticmethod
    def _handle_change_detected(
        db: Session,
        request: Request,
        actor: User,
        target: FimTarget,
        current_hash: str | None,
        reason: str,
        status_code: str,
        message: str,
    ) -> FimScanResult:
        """Internal helper to atomically emit MonitoringEvent, process Alert, and audit."""
        internal_source = get_or_create_internal_fim_source(db)
        severity = derive_fim_severity(target.asset)
        now = now_utc()

        title = f"File integrity violation on {target.target_code}"
        event_message = (
            f"Integrity check failed ({reason}) for target {target.target_code} "
            f"at relative path {target.relative_path}."
        )

        # Sanitized payload: NO file content, NO patient data, NO tokens
        payload = {
            "target_code": target.target_code,
            "relative_path": target.relative_path,
            "baseline_sha256": target.baseline_sha256,
            "current_sha256": current_hash,
            "reason": reason,
            "detected_at": now.isoformat(),
        }

        fingerprint = compute_event_fingerprint(
            source_id=internal_source.id,
            event_type=EventType.FILE_INTEGRITY_CHANGE.value,
            asset_id=target.asset_id,
            title=title,
            message=event_message,
        )

        from uuid import uuid4

        source_event_id = f"fim-{target.target_code}-{int(now.timestamp())}-{uuid4().hex[:8]}"

        try:
            event = MonitoringEvent(
                source_id=internal_source.id,
                asset_id=target.asset_id,
                source_event_id=source_event_id,
                event_type=EventType.FILE_INTEGRITY_CHANGE,
                severity=severity,
                title=title,
                message=event_message,
                occurred_at=now,
                received_at=now,
                fingerprint=fingerprint,
                payload_json=payload,
                created_at=now,
            )
            db.add(event)
            db.flush()

            # Process event through deterministic AlertEngine
            alerts = AlertEngine.process_event(db, event)
            first_alert = alerts[0] if alerts else None

            # Update target state: DO NOT alter baseline_sha256
            target.last_sha256 = current_hash or "MISSING"
            target.last_checked_at = now
            target.updated_at = now

            alert_id_str = first_alert.id if first_alert else "none"
            audit.record(
                db,
                request,
                action="FIM_CHANGE_DETECTED",
                resource=f"fim-target:{target.id}",
                decision="ALLOW",
                user=actor,
                detail=f"code={target.target_code} reason={reason} alert_id={alert_id_str}",
            )
            db.commit()

            return FimScanResult(
                target_id=target.id,
                target_code=target.target_code,
                relative_path=target.relative_path,
                status=status_code,
                baseline_sha256=target.baseline_sha256,
                current_sha256=current_hash,
                event_id=event.id,
                alert_id=first_alert.id if first_alert else None,
                message=message,
            )
        except Exception:
            db.rollback()
            raise

    @staticmethod
    def scan_all_enabled(
        db: Session,
        request: Request,
        actor: User,
    ) -> FimGlobalScanResponse:
        """Scan all enabled FIM targets sequentially."""
        targets = FimService.list_targets(db, enabled_only=True)
        results: list[FimScanResult] = []
        unchanged = 0
        changed = 0
        missing = 0
        errors = 0

        for target in targets:
            res = FimService.scan_target(db, request, actor, target)
            results.append(res)
            if res.status == "NO_CHANGE":
                unchanged += 1
            elif res.status == "CHANGED":
                changed += 1
            elif res.status == "MISSING":
                missing += 1
            else:
                errors += 1

        audit.record(
            db,
            request,
            action="FIM_SCAN_EXECUTED",
            resource="fim:global-scan",
            decision="ALLOW",
            user=actor,
            detail=(
                f"total={len(targets)} unchanged={unchanged} "
                f"changed={changed} missing={missing} errors={errors}"
            ),
        )
        db.commit()

        return FimGlobalScanResponse(
            total_targets=len(targets),
            scanned=len(targets),
            unchanged=unchanged,
            changed=changed,
            missing=missing,
            errors=errors,
            results=results,
        )
