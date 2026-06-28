from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .adapters import HeuristicScanAdapter, ScanAdapter
from .aggregate import aggregate_results
from .db import load_vulnerabilities
from .ingest import ingest_target
from .models import AgentResult, ScanReport, Vulnerability
from .partition import partition


async def scan_target(
    target: str | Path,
    vuln_db: str | Path,
    batch_size: int = 5,
    max_concurrent: int = 5,
    adapter: ScanAdapter | None = None,
) -> ScanReport:
    if max_concurrent < 1:
        raise ValueError("max_concurrent must be at least 1")

    vulnerabilities = load_vulnerabilities(vuln_db)
    sources = ingest_target(target)
    batches = partition(vulnerabilities, batch_size)
    adapter = adapter or HeuristicScanAdapter()
    semaphore = asyncio.Semaphore(max_concurrent)

    async def run_with_limit(agent_id: int, batch: list[Vulnerability]) -> AgentResult:
        async with semaphore:
            return await _run_agent(agent_id, batch, sources, adapter)

    results = await asyncio.gather(*(run_with_limit(i, batch) for i, batch in enumerate(batches)))
    findings, failed_agents = aggregate_results(list(results))
    return ScanReport(
        scan_id=str(uuid4()),
        target=str(target),
        timestamp=datetime.now(UTC),
        total_agents=len(batches),
        failed_agents=failed_agents,
        findings=findings,
        summary=None,
    )


async def _run_agent(
    agent_id: int,
    batch: list[Vulnerability],
    sources,
    adapter: ScanAdapter,
    retries: int = 1,
) -> AgentResult:
    last_error: Exception | None = None
    for _ in range(retries + 1):
        try:
            findings = await adapter.scan(agent_id, batch, sources)
            return AgentResult(
                agent_id=agent_id,
                vulnerability_batch=[vuln.id for vuln in batch],
                findings=findings,
                error=None,
            )
        except Exception as exc:
            last_error = exc
    return AgentResult(
        agent_id=agent_id,
        vulnerability_batch=[vuln.id for vuln in batch],
        findings=[],
        error=str(last_error),
    )

