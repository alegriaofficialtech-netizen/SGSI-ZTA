from collections.abc import Generator
from datetime import UTC, datetime

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


def now_utc() -> datetime:
    """Database timestamps use naive UTC consistently, including SQLite tests."""
    return datetime.now(UTC).replace(tzinfo=None)


class ApplicationSession(Session):
    """Keep immutable M5 updates out of legacy ORM bulk persistence helpers."""

    @staticmethod
    def _reject_immutable_bulk_update(mapper) -> None:
        # Import only on a helper call, after database and model initialization.
        from app.models.policies import PolicyDecision, PolicyVersion

        model = inspect(mapper).class_
        if issubclass(model, (PolicyDecision, PolicyVersion)):
            raise ValueError(f"{model.__name__} is append-only")

    def bulk_update_mappings(self, mapper, mappings) -> None:
        self._reject_immutable_bulk_update(mapper)
        return super().bulk_update_mappings(mapper, mappings)

    def bulk_save_objects(
        self, objects, return_defaults=False, update_changed_only=True, preserve_order=True,
    ) -> None:
        # Preflight the whole iterable before any mixed-batch insert/update.
        objects = list(objects)
        for obj in objects:
            state = inspect(obj)
            if state.key is not None:
                self._reject_immutable_bulk_update(state.mapper)
        return super().bulk_save_objects(
            objects, return_defaults=return_defaults,
            update_changed_only=update_changed_only, preserve_order=preserve_order,
        )


class Base(DeclarativeBase):
    pass


url = get_settings().database_url
engine = create_engine(
    url,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
)

if url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(bind=engine, class_=ApplicationSession, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as db:
        yield db
