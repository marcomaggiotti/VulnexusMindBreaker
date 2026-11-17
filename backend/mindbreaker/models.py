"""Shared data models: target configuration and assessment results."""

from __future__ import annotations

import enum
import json
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, model_validator


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def escalate(self) -> "Severity":
        """One level more severe (critical stays critical)."""
        order = list(_SEVERITY_RANK)
        return order[max(0, order.index(self) - 1)]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class ToolSpec(BaseModel):
    """A tool/function the AI application can call."""

    name: str
    description: str = ""
    # True when the tool changes state or reaches non-public data
    # (send email, run SQL, issue refund, read files...).
    sensitive: bool = False


class TargetConfig(BaseModel):
    """An AI application registered for assessment."""

    name: str = Field(min_length=1, max_length=120)
    description: str = ""

    # openai_chat: any OpenAI-compatible /chat/completions endpoint.
    # http_json:   arbitrary JSON API, described by request_template/response_path.
    # demo:        built-in simulated chatbot, no network (for trying the platform).
    connector: Literal["openai_chat", "http_json", "demo"] = "openai_chat"
    endpoint: str | None = None
    model: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=60, gt=0, le=600)

    # The application's system prompt. With openai_chat/demo the engine sends it
    # (plus a canary) so leakage is provable. With http_json the application owns
    # the prompt; provide it here only so leaks can be recognised.
    system_prompt: str | None = None
    send_system_prompt: bool = True

    # http_json only. Strings "{{prompt}}" / "{{system_prompt}}" inside the template
    # are substituted. response_path is a dotted path, e.g. "data.reply" or
    # "choices.0.message.content"; omit it to use the raw response body.
    request_template: dict[str, Any] | None = None
    response_path: str | None = None

    # Context used to judge *impact*, not just model behaviour.
    secrets: list[str] = Field(default_factory=list)  # strings that must never be output
    tools: list[ToolSpec] = Field(default_factory=list)
    knowledge_sources: list[str] = Field(default_factory=list)

    demo_profile: Literal["vulnerable", "partial", "hardened"] = "vulnerable"

    # Explicit confirmation that the caller may test this system.
    authorized: bool = False

    @model_validator(mode="after")
    def _validate(self) -> "TargetConfig":
        if not self.authorized:
            raise ValueError(
                "authorized must be true: confirm you own this system or have "
                "written permission to test it"
            )
        if self.connector == "demo":
            return self
        if not self.endpoint:
            raise ValueError(f"endpoint is required for connector '{self.connector}'")
        parsed = urlparse(self.endpoint)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("endpoint must be an http(s) URL")
        if self.connector == "openai_chat" and not self.model:
            raise ValueError("model is required for connector 'openai_chat'")
        if self.connector == "http_json":
            if not self.request_template:
                raise ValueError("request_template is required for connector 'http_json'")
            if "{{prompt}}" not in json.dumps(self.request_template):
                raise ValueError('request_template must contain the placeholder "{{prompt}}"')
        return self

    @property
    def engine_controls_system_prompt(self) -> bool:
        if self.connector == "demo":
            return True
        return self.connector == "openai_chat" and self.send_system_prompt

    def redacted(self) -> dict[str, Any]:
        """Config safe to return from the API: credentials and secrets masked."""
        data = self.model_dump()
        data["headers"] = {k: "***" for k in self.headers}
        data["secrets"] = ["***" for _ in self.secrets]
        return data


class Detection(BaseModel):
    detector: str
    detail: str


class Evidence(BaseModel):
    case_id: str
    attempt: int
    transcript: list[dict[str, str]]
    detections: list[Detection]


class Finding(BaseModel):
    probe_id: str
    title: str
    category: str
    severity: Severity
    score: float  # 0-10
    success_rate: float  # share of attack attempts that succeeded
    hits: int
    runs: int
    owasp: str
    atlas: str
    description: str
    impact: str
    remediation: str
    evidence: list[Evidence]


class ProbeOutcome(BaseModel):
    probe_id: str
    title: str
    category: str
    status: Literal["vulnerable", "passed", "skipped", "error"]
    runs: int = 0
    hits: int = 0
    errors: int = 0
    note: str = ""


class AssessmentResult(BaseModel):
    target_name: str
    started_at: str
    finished_at: str
    risk_score: int  # 0-100
    risk_rating: str
    severity_counts: dict[str, int]
    outcomes: list[ProbeOutcome]
    findings: list[Finding]


class RunOptions(BaseModel):
    probe_ids: list[str] | None = None
    categories: list[str] | None = None
    # Models are stochastic: each test case is repeated and the hit rate reported.
    attempts: int = Field(default=2, ge=1, le=10)
    concurrency: int = Field(default=4, ge=1, le=32)
