from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from .db import load_vulnerabilities
from .ingest import ingest_target
from .models import PromptBatch, ScanManifest, SourceFile, Vulnerability
from .partition import partition
from .platforms import detect_platform_tags, filter_vulnerabilities_by_platform


SCHEMA_EXAMPLE = [
    {
        "vulnerability_id": "CWE-89",
        "vulnerability_name": "SQL Injection",
        "file": "src/db.py",
        "line_start": 42,
        "line_end": 42,
        "severity": "critical",
        "confidence": "high",
        "description": "User input is interpolated into a SQL query.",
        "suggested_fix": "Use parameterized queries.",
    }
]


def prepare_scan(
    target: str | Path,
    vuln_db: str | Path,
    output_dir: str | Path,
    batch_size: int = 5,
    platform_filter: str = "none",
    platform_tags: list[str] | None = None,
    include_generic_platforms: bool = True,
) -> ScanManifest:
    all_vulnerabilities = load_vulnerabilities(vuln_db)
    sources = ingest_target(target)
    detected_tags = detect_platform_tags(sources)
    requested_tags = platform_tags or []
    vulnerabilities = filter_vulnerabilities_by_platform(
        all_vulnerabilities,
        mode=platform_filter,
        detected_tags=detected_tags,
        requested_tags=requested_tags,
        include_generic=include_generic_platforms,
    )
    batches = partition(vulnerabilities, batch_size)

    out = Path(output_dir)
    prompts_dir = out / "prompts"
    results_dir = out / "results"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    prompt_batches: list[PromptBatch] = []
    for agent_id, batch in enumerate(batches):
        prompt_path = prompts_dir / f"agent-{agent_id}.md"
        result_path = results_dir / f"agent-{agent_id}.json"
        prompt_path.write_text(build_agent_prompt(agent_id, batch, sources))
        prompt_batches.append(
            PromptBatch(
                agent_id=agent_id,
                vulnerability_ids=[vuln.id for vuln in batch],
                prompt_path=str(prompt_path),
                result_path=str(result_path),
            )
        )

    manifest = ScanManifest(
        scan_id=str(uuid4()),
        target=str(target),
        vulnerability_db=str(vuln_db),
        batch_size=batch_size,
        total_agents=len(batches),
        total_vulnerabilities=len(all_vulnerabilities),
        selected_vulnerabilities=len(vulnerabilities),
        platform_filter=platform_filter,
        detected_platform_tags=detected_tags,
        requested_platform_tags=requested_tags,
        include_generic_platforms=include_generic_platforms,
        prompts_dir=str(prompts_dir),
        results_dir=str(results_dir),
        batches=prompt_batches,
    )
    (out / "scan_manifest.json").write_text(manifest.model_dump_json(indent=2))
    (out / "orchestrator.md").write_text(build_orchestrator_prompt(manifest))
    return manifest


def build_agent_prompt(agent_id: int, vulnerabilities: list[Vulnerability], sources: list[SourceFile]) -> str:
    vuln_block = "\n\n".join(_format_vulnerability(vuln) for vuln in vulnerabilities)
    target_block = "\n\n".join(_format_source(source) for source in sources)
    schema = json.dumps(SCHEMA_EXAMPLE, indent=2)
    return f"""# parallel-patch Agent {agent_id}

You are a focused security review subagent. Analyze only the target content below and only for the vulnerabilities assigned to you.

## Assigned Vulnerabilities

{vuln_block}

## Target Content

{target_block}

## Rules

- Report only vulnerabilities from your assigned list.
- Prefer findings on changed diff lines when the target is a patch.
- Do not report style, quality, dependency, or unrelated security issues.
- Use exact file paths and line numbers from the target content.
- Return only a JSON array. Do not include Markdown fences, prose, or a summary.
- If there are no findings, return [].

## Output Schema

{schema}
"""


def build_orchestrator_prompt(manifest: ScanManifest) -> str:
    lines = [
        "# parallel-patch Orchestrator",
        "",
        "Spawn one Codex subagent per prompt listed below. Each subagent should read its prompt, analyze independently, and write only its JSON array result to the matching result path.",
        "",
        f"- Scan ID: `{manifest.scan_id}`",
        f"- Target: `{manifest.target}`",
        f"- Vulnerability DB: `{manifest.vulnerability_db}`",
        f"- Platform filter: `{manifest.platform_filter}`",
        f"- Detected platform tags: {', '.join(manifest.detected_platform_tags) or 'none'}",
        f"- Requested platform tags: {', '.join(manifest.requested_platform_tags) or 'none'}",
        f"- Vulnerabilities selected: {manifest.selected_vulnerabilities}/{manifest.total_vulnerabilities}",
        f"- Total agents: {manifest.total_agents}",
        "",
        "## Agent Work Items",
        "",
    ]
    for batch in manifest.batches:
        lines.append(
            f"- Agent {batch.agent_id}: prompt `{batch.prompt_path}`, result `{batch.result_path}`, vulnerabilities {', '.join(batch.vulnerability_ids)}"
        )
    lines += [
        "",
        "After all result files exist, aggregate them with:",
        "",
        "```bash",
        f"python -m parallel_patch.cli aggregate --manifest {Path(manifest.prompts_dir).parent / 'scan_manifest.json'} --output-dir {Path(manifest.prompts_dir).parent / 'report'} --format both",
        "```",
        "",
    ]
    return "\n".join(lines)


def _format_vulnerability(vuln: Vulnerability) -> str:
    indicators = "\n".join(f"  - {indicator}" for indicator in vuln.indicators) or "  - None provided"
    return f"""### {vuln.id}: {vuln.name}

- Severity: {vuln.severity}
- Description: {vuln.description}
- Indicators:
{indicators}"""


def _format_source(source: SourceFile) -> str:
    lines = "\n".join(f"{line.number}: {line.text}" for line in source.lines)
    return f"""### {source.path}

```text
{lines}
```"""
