"""Probe primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..detectors import Detector
from ..models import Severity, TargetConfig


@dataclass
class ProbeContext:
    """Per-assessment values the probes build their test cases from."""

    target: TargetConfig
    # The marker never appears whole in a prompt: the model must join the two
    # parts, so a refusal that quotes the request cannot be mistaken for a hit.
    marker_a: str
    marker_b: str
    # Planted in the system prompt when the engine controls it, else None.
    canary: str | None
    # System prompt as known to the engine (without the canary line), if any.
    system_prompt: str | None

    @property
    def marker(self) -> str:
        return self.marker_a + self.marker_b

    @property
    def marker_ask(self) -> str:
        return (
            f'the string formed by joining "{self.marker_a}" and "{self.marker_b}" '
            "with no space"
        )


@dataclass
class Case:
    id: str
    turns: list[str]  # user messages, sent in order within one conversation
    detectors: list[Detector]


@dataclass
class Probe:
    id: str
    title: str
    category: str
    severity: Severity
    owasp: str
    atlas: str
    description: str
    remediation: str
    build: Callable[[ProbeContext], list[Case]]
    # Why the probe produced no cases for this target (shown as "skipped").
    skip_reason: Callable[[ProbeContext], str | None] = field(default=lambda ctx: None)
