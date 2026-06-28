from __future__ import annotations

import abc
import asyncio
import json
import re
from typing import Any

from pydantic import TypeAdapter

from .models import SourceFile, Vulnerability, VulnerabilityFinding


_finding_list_adapter = TypeAdapter(list[VulnerabilityFinding])


class ScanAdapter(abc.ABC):
    @abc.abstractmethod
    async def scan(
        self, agent_id: int, vulnerability_batch: list[Vulnerability], sources: list[SourceFile]
    ) -> list[VulnerabilityFinding]:
        raise NotImplementedError


class HeuristicScanAdapter(ScanAdapter):
    """Local deterministic adapter for demos and tests."""

    async def scan(
        self, agent_id: int, vulnerability_batch: list[Vulnerability], sources: list[SourceFile]
    ) -> list[VulnerabilityFinding]:
        await asyncio.sleep(0)
        findings: list[VulnerabilityFinding] = []
        for vuln in vulnerability_batch:
            patterns = _patterns_for(vuln)
            for source in sources:
                for line in source.lines:
                    if any(pattern.search(line.text) for pattern in patterns):
                        findings.append(
                            VulnerabilityFinding(
                                vulnerability_id=vuln.id,
                                vulnerability_name=vuln.name,
                                file=source.path,
                                line_start=line.number,
                                line_end=line.number,
                                severity=vuln.severity,
                                confidence="medium",
                                description=f"Potential {vuln.name}: matched indicator in source line.",
                                suggested_fix=_suggested_fix(vuln.id),
                            )
                        )
        return findings


def parse_findings_json(raw: str | list[dict[str, Any]]) -> list[VulnerabilityFinding]:
    data = json.loads(raw) if isinstance(raw, str) else raw
    return _finding_list_adapter.validate_python(data)


def _patterns_for(vuln: Vulnerability) -> list[re.Pattern[str]]:
    indicators = vuln.indicators or [vuln.name, vuln.description]
    return [re.compile(re.escape(indicator), re.IGNORECASE) for indicator in indicators if indicator.strip()]


def _suggested_fix(vulnerability_id: str) -> str | None:
    fixes = {
        "CWE-22": "Normalize and constrain file paths to an expected base directory.",
        "CWE-79": "Escape or sanitize untrusted input before rendering HTML.",
        "CWE-89": "Use parameterized queries or a safe ORM query API.",
    }
    return fixes.get(vulnerability_id)

