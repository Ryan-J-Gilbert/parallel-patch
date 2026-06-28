from __future__ import annotations

import json
from pathlib import Path

from .models import ScanReport


def write_report(report: ScanReport, output_dir: str | Path, output_format: str = "both") -> list[Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if output_format in {"json", "both"}:
        path = out / "report.json"
        path.write_text(report.model_dump_json(indent=2))
        written.append(path)
    if output_format in {"markdown", "both"}:
        path = out / "report.md"
        path.write_text(render_markdown(report))
        written.append(path)
    if output_format not in {"json", "markdown", "both"}:
        raise ValueError("format must be one of: json, markdown, both")
    return written


def render_markdown(report: ScanReport) -> str:
    lines = [
        f"# parallel-patch Report",
        "",
        f"- Scan ID: `{report.scan_id}`",
        f"- Target: `{report.target}`",
        f"- Agents: {report.total_agents}",
        f"- Failed agents: {report.failed_agents}",
        f"- Findings: {len(report.findings)}",
        "",
    ]
    if report.summary:
        lines += ["## Summary", "", report.summary, ""]
    if not report.findings:
        return "\n".join(lines + ["No findings detected.", ""])

    lines += ["## Findings", ""]
    for finding in report.findings:
        location = f"{finding.file}:{finding.line_start}"
        if finding.line_end and finding.line_end != finding.line_start:
            location = f"{finding.file}:{finding.line_start}-{finding.line_end}"
        lines += [
            f"### {finding.severity.upper()} {finding.vulnerability_id}: {finding.vulnerability_name}",
            "",
            f"- Location: `{location}`",
            f"- Confidence: {finding.confidence}",
            f"- Description: {finding.description}",
        ]
        if finding.suggested_fix:
            lines.append(f"- Suggested fix: {finding.suggested_fix}")
        lines.append("")
    return "\n".join(lines)


def report_to_json(report: ScanReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2)
