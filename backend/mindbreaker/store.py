"""Persistence (SQLAlchemy). SQLite by default; set MINDBREAKER_DATABASE_URL for PostgreSQL."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy.pool import StaticPool

from .models import AssessmentResult, RunOptions, TargetConfig


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class TargetRow(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    name: Mapped[str] = mapped_column(String(120))
    config: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(String(32), default=_now)


class AssessmentRow(Base):
    __tablename__ = "assessments"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    target_name: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|completed|failed
    done: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)
    options: Mapped[dict[str, Any]] = mapped_column(JSON)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), default=_now)
    finished_at: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Store:
    def __init__(self, url: str = "sqlite:///mindbreaker.db"):
        kwargs: dict[str, Any] = {}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            if ":memory:" in url or url == "sqlite://":
                kwargs["poolclass"] = StaticPool
        self.engine = create_engine(url, **kwargs)
        Base.metadata.create_all(self.engine)

    def _session(self) -> Session:
        return Session(self.engine, expire_on_commit=False)

    # targets
    def create_target(self, config: TargetConfig) -> TargetRow:
        with self._session() as session:
            row = TargetRow(name=config.name, config=config.model_dump())
            session.add(row)
            session.commit()
            return row

    def list_targets(self) -> list[TargetRow]:
        with self._session() as session:
            return list(session.scalars(select(TargetRow).order_by(TargetRow.created_at.desc())))

    def get_target(self, target_id: str) -> TargetRow | None:
        with self._session() as session:
            return session.get(TargetRow, target_id)

    def delete_target(self, target_id: str) -> bool:
        with self._session() as session:
            row = session.get(TargetRow, target_id)
            if row is None:
                return False
            for assessment in session.scalars(
                select(AssessmentRow).where(AssessmentRow.target_id == target_id)
            ):
                session.delete(assessment)
            session.delete(row)
            session.commit()
            return True

    # assessments
    def create_assessment(self, target: TargetRow, options: RunOptions) -> AssessmentRow:
        with self._session() as session:
            row = AssessmentRow(
                target_id=target.id, target_name=target.name, options=options.model_dump()
            )
            session.add(row)
            session.commit()
            return row

    def list_assessments(self, limit: int = 100) -> list[AssessmentRow]:
        with self._session() as session:
            query = select(AssessmentRow).order_by(AssessmentRow.created_at.desc()).limit(limit)
            return list(session.scalars(query))

    def get_assessment(self, assessment_id: str) -> AssessmentRow | None:
        with self._session() as session:
            return session.get(AssessmentRow, assessment_id)

    def _update(self, assessment_id: str, **fields: Any) -> None:
        with self._session() as session:
            row = session.get(AssessmentRow, assessment_id)
            if row is None:
                return
            for key, value in fields.items():
                setattr(row, key, value)
            session.commit()

    def set_progress(self, assessment_id: str, done: int, total: int) -> None:
        self._update(assessment_id, status="running", done=done, total=total)

    def complete(self, assessment_id: str, result: AssessmentResult) -> None:
        self._update(
            assessment_id,
            status="completed",
            result=result.model_dump(mode="json"),
            finished_at=_now(),
        )

    def fail(self, assessment_id: str, error: str) -> None:
        self._update(assessment_id, status="failed", error=error, finished_at=_now())

    def fail_interrupted(self) -> None:
        """Assessments run in-process; any still 'running' at startup were cut off."""
        with self._session() as session:
            query = select(AssessmentRow).where(AssessmentRow.status.in_(("queued", "running")))
            for row in session.scalars(query):
                row.status = "failed"
                row.error = "interrupted by a server restart"
                row.finished_at = _now()
            session.commit()
