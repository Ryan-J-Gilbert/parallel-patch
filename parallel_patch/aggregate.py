from __future__ import annotations

from .models import AgentResult, ScanReport, VulnerabilityFinding


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def aggregate_results(results: list[AgentResult]) -> tuple[list[VulnerabilityFinding], int]:
    failed_agents = sum(1 for result in results if result.error)
    deduped: list[VulnerabilityFinding] = []
    for result in results:
        for finding in result.findings:
            existing = _find_duplicate(deduped, finding)
            if existing is None:
                deduped.append(finding)
            else:
                _merge_into(existing, finding)
    deduped.sort(key=lambda f: (SEVERITY_ORDER[f.severity], CONFIDENCE_ORDER[f.confidence], f.file, f.line_start))
    return deduped, failed_agents


def finalize_report(report: ScanReport, results: list[AgentResult]) -> ScanReport:
    findings, failed_agents = aggregate_results(results)
    return report.model_copy(update={"findings": findings, "failed_agents": failed_agents})


def _find_duplicate(existing: list[VulnerabilityFinding], candidate: VulnerabilityFinding):
    for finding in existing:
        if (
            finding.vulnerability_id == candidate.vulnerability_id
            and finding.file == candidate.file
            and _ranges_overlap(finding.line_start, finding.line_end, candidate.line_start, candidate.line_end)
        ):
            return finding
    return None


def _ranges_overlap(a_start: int, a_end: int | None, b_start: int, b_end: int | None) -> bool:
    a_end = a_end or a_start
    b_end = b_end or b_start
    return a_start <= b_end and b_start <= a_end


def _merge_into(existing: VulnerabilityFinding, candidate: VulnerabilityFinding) -> None:
    if SEVERITY_ORDER[candidate.severity] < SEVERITY_ORDER[existing.severity]:
        existing.severity = candidate.severity
    if CONFIDENCE_ORDER[candidate.confidence] < CONFIDENCE_ORDER[existing.confidence]:
        existing.confidence = candidate.confidence
    existing.line_start = min(existing.line_start, candidate.line_start)
    existing.line_end = max(existing.line_end or existing.line_start, candidate.line_end or candidate.line_start)
    if candidate.suggested_fix and not existing.suggested_fix:
        existing.suggested_fix = candidate.suggested_fix

