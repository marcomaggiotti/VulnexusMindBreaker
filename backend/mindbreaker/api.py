"""REST API for the security control center."""

from __future__ import annotations

import os
import secrets
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Response

from . import __version__
from .engine import run_assessment, select_probes
from .models import AssessmentResult, RunOptions, TargetConfig
from .probes import PROBES
from .report import to_html, to_markdown
from .store import AssessmentRow, Store, TargetRow


class AssessmentRequest(RunOptions):
    target_id: str


def _target_out(row: TargetRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "created_at": row.created_at,
        "config": TargetConfig(**row.config).redacted(),
    }


def _assessment_out(row: AssessmentRow, full: bool = False) -> dict[str, Any]:
    result = row.result or {}
    data: dict[str, Any] = {
        "id": row.id,
        "target_id": row.target_id,
        "target_name": row.target_name,
        "status": row.status,
        "done": row.done,
        "total": row.total,
        "error": row.error,
        "created_at": row.created_at,
        "finished_at": row.finished_at,
        "risk_score": result.get("risk_score"),
        "risk_rating": result.get("risk_rating"),
        "severity_counts": result.get("severity_counts"),
    }
    if full:
        data["options"] = row.options
        data["result"] = row.result
    return data


def create_app(database_url: str | None = None, api_key: str | None = None) -> FastAPI:
    store = Store(database_url or os.environ.get("MINDBREAKER_DATABASE_URL", "sqlite:///mindbreaker.db"))
    store.fail_interrupted()
    required_key = api_key if api_key is not None else os.environ.get("MINDBREAKER_API_KEY")

    def check_key(x_api_key: str | None = Header(default=None)) -> None:
        if required_key and not secrets.compare_digest(x_api_key or "", required_key):
            raise HTTPException(status_code=401, detail="missing or invalid X-API-Key")

    app = FastAPI(title="Vulnexus MindBreaker", version=__version__)
    api = dict(dependencies=[Depends(check_key)])

    async def execute(assessment_id: str) -> None:
        row = store.get_assessment(assessment_id)
        target = store.get_target(row.target_id) if row else None
        if row is None or target is None:
            return
        try:
            result = await run_assessment(
                TargetConfig(**target.config),
                RunOptions(**row.options),
                progress=lambda done, total: store.set_progress(assessment_id, done, total),
            )
            store.complete(assessment_id, result)
        except Exception as exc:  # the run must end in a terminal state
            store.fail(assessment_id, f"{type(exc).__name__}: {exc}")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/probes", **api)
    def list_probes() -> list[dict[str, str]]:
        return [
            {
                "id": p.id, "title": p.title, "category": p.category,
                "severity": p.severity.value, "owasp": p.owasp, "atlas": p.atlas,
                "description": p.description,
            }
            for p in PROBES
        ]

    @app.post("/api/targets", status_code=201, **api)
    def create_target(config: TargetConfig) -> dict[str, Any]:
        return _target_out(store.create_target(config))

    @app.get("/api/targets", **api)
    def list_targets() -> list[dict[str, Any]]:
        return [_target_out(row) for row in store.list_targets()]

    @app.get("/api/targets/{target_id}", **api)
    def get_target(target_id: str) -> dict[str, Any]:
        row = store.get_target(target_id)
        if row is None:
            raise HTTPException(404, "target not found")
        return _target_out(row)

    @app.delete("/api/targets/{target_id}", status_code=204, **api)
    def delete_target(target_id: str) -> Response:
        if not store.delete_target(target_id):
            raise HTTPException(404, "target not found")
        return Response(status_code=204)

    @app.post("/api/assessments", status_code=202, **api)
    def start_assessment(request: AssessmentRequest, background: BackgroundTasks) -> dict[str, Any]:
        target = store.get_target(request.target_id)
        if target is None:
            raise HTTPException(404, "target not found")
        options = RunOptions(**request.model_dump(exclude={"target_id"}))
        try:
            if not select_probes(options):
                raise ValueError("no probes match the selection")
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        row = store.create_assessment(target, options)
        background.add_task(execute, row.id)
        return _assessment_out(row)

    @app.get("/api/assessments", **api)
    def list_assessments() -> list[dict[str, Any]]:
        return [_assessment_out(row) for row in store.list_assessments()]

    def _get(assessment_id: str) -> AssessmentRow:
        row = store.get_assessment(assessment_id)
        if row is None:
            raise HTTPException(404, "assessment not found")
        return row

    @app.get("/api/assessments/{assessment_id}", **api)
    def get_assessment(assessment_id: str) -> dict[str, Any]:
        return _assessment_out(_get(assessment_id), full=True)

    @app.get("/api/assessments/{assessment_id}/report", **api)
    def get_report(assessment_id: str, format: str = "html") -> Response:
        row = _get(assessment_id)
        if row.status != "completed" or not row.result:
            raise HTTPException(409, f"assessment is {row.status}; no report available")
        result = AssessmentResult(**row.result)
        name = f"mindbreaker-{row.id[:8]}"
        if format == "json":
            body, media, ext = result.model_dump_json(indent=2), "application/json", "json"
        elif format == "md":
            body, media, ext = to_markdown(result), "text/markdown", "md"
        elif format == "html":
            body, media, ext = to_html(result), "text/html", "html"
        else:
            raise HTTPException(422, "format must be html, md or json")
        return Response(
            body,
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="{name}.{ext}"',
                # Reports embed attacker-style payloads as escaped text; belt and braces.
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
            },
        )

    @app.get("/api/dashboard", **api)
    def dashboard() -> dict[str, Any]:
        assessments = store.list_assessments(limit=500)
        # Current exposure = findings from the latest completed assessment per target.
        latest: dict[str, AssessmentRow] = {}
        for row in assessments:  # newest first
            if row.status == "completed" and row.target_id not in latest:
                latest[row.target_id] = row
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        categories: dict[str, int] = {}
        for row in latest.values():
            for finding in (row.result or {}).get("findings", []):
                counts[finding["severity"]] += 1
                categories[finding["category"]] = categories.get(finding["category"], 0) + 1
        return {
            "targets": len(store.list_targets()),
            "assessments": len(assessments),
            "running": sum(1 for row in assessments if row.status in ("queued", "running")),
            "open_findings": counts,
            "findings_by_category": categories,
            "target_risk": [
                {
                    "target_id": row.target_id, "target_name": row.target_name,
                    "assessment_id": row.id, "risk_score": (row.result or {}).get("risk_score"),
                    "risk_rating": (row.result or {}).get("risk_rating"),
                    "finished_at": row.finished_at,
                }
                for row in latest.values()
            ],
            "recent": [_assessment_out(row) for row in assessments[:10]],
        }

    return app


class _LazyApp:
    """ASGI entry point for `uvicorn mindbreaker.api:app` (built on first use)."""

    _app: FastAPI | None = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if self._app is None:
            self._app = create_app()
        await self._app(scope, receive, send)


app = _LazyApp()
