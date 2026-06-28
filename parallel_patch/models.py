from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


Severity = Literal["critical", "high", "medium", "low", "informational"]
Confidence = Literal["high", "medium", "low"]


class Vulnerability(BaseModel):
    id: str
    name: str
    severity: Severity
    description: str
    indicators: list[str] = Field(default_factory=list)
    source: str | None = None
    rank: int | None = None
    status: str | None = None
    weakness_abstraction: str | None = None
    applicable_platforms: str | None = None
    platform_tags: list[str] = Field(default_factory=list)

    @field_validator("id", "name", "description")
    @classmethod
    def require_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value


class VulnerabilityFinding(BaseModel):
    vulnerability_id: str
    vulnerability_name: str
    file: str
    line_start: int = Field(ge=1)
    line_end: int | None = Field(default=None, ge=1)
    severity: Severity
    confidence: Confidence
    description: str
    suggested_fix: str | None = None

    @field_validator("line_end")
    @classmethod
    def line_end_must_not_precede_start(cls, value: int | None, info):
        if value is not None and "line_start" in info.data and value < info.data["line_start"]:
            raise ValueError("line_end must be greater than or equal to line_start")
        return value


class AgentResult(BaseModel):
    agent_id: int
    vulnerability_batch: list[str]
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    error: str | None = None


class ScanReport(BaseModel):
    model_config = ConfigDict(json_encoders={datetime: lambda value: value.isoformat()})

    scan_id: str
    target: str
    timestamp: datetime
    total_agents: int
    failed_agents: int
    findings: list[VulnerabilityFinding]
    summary: str | None = None


class SourceLine(BaseModel):
    number: int = Field(ge=1)
    text: str


class SourceFile(BaseModel):
    path: str
    lines: list[SourceLine]

    @property
    def content(self) -> str:
        return "\n".join(line.text for line in self.lines)


class PromptBatch(BaseModel):
    agent_id: int
    vulnerability_ids: list[str]
    prompt_path: str
    result_path: str


class ScanManifest(BaseModel):
    scan_id: str
    target: str
    vulnerability_db: str
    batch_size: int
    total_agents: int
    total_vulnerabilities: int = 0
    selected_vulnerabilities: int = 0
    platform_filter: str = "none"
    detected_platform_tags: list[str] = Field(default_factory=list)
    requested_platform_tags: list[str] = Field(default_factory=list)
    include_generic_platforms: bool = True
    prompts_dir: str
    results_dir: str
    batches: list[PromptBatch]
