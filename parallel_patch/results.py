from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import TypeAdapter

from .adapters import parse_findings_json
from .aggregate import aggregate_results
from .models import AgentResult, ScanManifest, ScanReport
from .output import write_report


_manifest_adapter = TypeAdapter(ScanManifest)


def load_manifest(path: str | Path) -> ScanManifest:
    return _manifest_adapter.validate_json(Path(path).read_text())


def load_agent_results(manifest: ScanManifest) -> list[AgentResult]:
    results: list[AgentResult] = []
    for batch in manifest.batches:
        result_path = Path(batch.result_path)
        if not result_path.exists():
            results.append(
                AgentResult(
                    agent_id=batch.agent_id,
                    vulnerability_batch=batch.vulnerability_ids,
                    findings=[],
                    error=f"missing result file: {result_path}",
                )
            )
            continue
        try:
            payload = json.loads(result_path.read_text())
            if isinstance(payload, dict) and {"agent_id", "vulnerability_batch", "findings"}.issubset(payload):
                results.append(AgentResult.model_validate(payload))
            else:
                results.append(
                    AgentResult(
                        agent_id=batch.agent_id,
                        vulnerability_batch=batch.vulnerability_ids,
                        findings=parse_findings_json(payload),
                        error=None,
                    )
                )
        except Exception as exc:
            results.append(
                AgentResult(
                    agent_id=batch.agent_id,
                    vulnerability_batch=batch.vulnerability_ids,
                    findings=[],
                    error=str(exc),
                )
            )
    return results


def aggregate_manifest_results(
    manifest_path: str | Path,
    output_dir: str | Path,
    output_format: str = "both",
) -> ScanReport:
    manifest = load_manifest(manifest_path)
    agent_results = load_agent_results(manifest)
    findings, failed_agents = aggregate_results(agent_results)
    report = ScanReport(
        scan_id=manifest.scan_id,
        target=manifest.target,
        timestamp=datetime.now(UTC),
        total_agents=manifest.total_agents,
        failed_agents=failed_agents,
        findings=findings,
        summary=None,
    )
    write_report(report, output_dir, output_format)
    return report
