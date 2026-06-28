# parallel-patch

`parallel-patch` prepares focused security-review prompts for Codex subagents, then aggregates their JSON findings into PR-friendly reports.

The project is intentionally lightweight. Python handles deterministic setup work: loading CWE data, filtering it, batching it, writing prompts, validating results, deduplicating findings, and rendering reports. Codex agents do the actual code review.

## Current Workflow

```text
target diff or source tree
        +
CWE vulnerability database
        |
        v
prepare prompts and scan_manifest.json
        |
        v
Codex spawns one subagent per prompt
        |
        v
subagents write JSON findings
        |
        v
aggregate report.json and report.md
```

## Repository Layout

- `parallel_patch/`: Python package for ingestion, batching, prompting, filtering, aggregation, and reporting.
- `scripts/convert_cwe_csv.py`: MITRE CWE CSV to `parallel-patch` JSON converter.
- `data/cwe_top25_mitre.json`: Generated MITRE CWE Top 25 scan DB.
- `data/cwe_software_development.json`: Generated 399-row MITRE software-development CWE scan DB.
- `docs/data.md`: Data-source, conversion, platform-filtering, and batch-size notes.
- `skills/parallel-patch/SKILL.md`: Codex skill instructions.
- `tests/`: Unit/integration tests and tiny fixtures.

## Install or Run Locally

Run from the repository root:

```bash
python3 -m unittest discover -s tests
```

Optional editable install:

```bash
python3 -m pip install -e .
parallel-patch --help
```

You can also run without installing:

```bash
python3 -m parallel_patch.cli --help
```

## Prepare a Codex Scan

Use the MITRE Top 25 DB for the first end-to-end test:

```bash
python3 -m parallel_patch.cli prepare \
  --target tests/fixtures/change.diff \
  --vuln-db data/cwe_top25_mitre.json \
  --batch-size 5 \
  --output-dir parallel-patch-run
```

This writes:

```text
parallel-patch-run/scan_manifest.json
parallel-patch-run/orchestrator.md
parallel-patch-run/prompts/agent-0.md
parallel-patch-run/results/
```

Open `parallel-patch-run/orchestrator.md`. It tells Codex which subagents to spawn and where each subagent should write its JSON result.

## Codex Message to Try It

After running `prepare`, send this to Codex:

```text
Read parallel-patch-run/orchestrator.md and execute the parallel-patch scan exactly as instructed: spawn one subagent per listed prompt, have each subagent write only its JSON array to the assigned result path, then aggregate the results.
```

Each subagent result must be a JSON array of findings:

```json
[
  {
    "vulnerability_id": "CWE-89",
    "vulnerability_name": "SQL Injection",
    "file": "app.py",
    "line_start": 2,
    "line_end": 3,
    "severity": "critical",
    "confidence": "high",
    "description": "Changed lines build and execute an interpolated SQL query.",
    "suggested_fix": "Use parameterized queries."
  }
]
```

## Aggregate Results

Once result files exist:

```bash
python3 -m parallel_patch.cli aggregate \
  --manifest parallel-patch-run/scan_manifest.json \
  --output-dir parallel-patch-run/report \
  --format both
```

Final outputs:

```text
parallel-patch-run/report/report.json
parallel-patch-run/report/report.md
```

## CWE Data Conversion

The local source files used so far are:

- `/Users/ryan/Downloads/1435.csv`: MITRE CWE Top 25, 25 rows.
- `/Users/ryan/Downloads/699.csv`: MITRE software-development CWE view, 399 rows.

Regenerate Top 25:

```bash
python3 scripts/convert_cwe_csv.py \
  /Users/ryan/Downloads/1435.csv \
  data/cwe_top25_mitre.json \
  --source "MITRE CWE Top 25"
```

Regenerate the larger software-development DB:

```bash
python3 scripts/convert_cwe_csv.py \
  /Users/ryan/Downloads/699.csv \
  data/cwe_software_development.json \
  --severity-strategy medium \
  --source "MITRE CWE Software Development View"
```

The converter keeps compact prompt-safe fields:

- `id`
- `name`
- `severity`
- `description`
- `indicators`
- `rank`
- `status`
- `weakness_abstraction`
- `applicable_platforms`
- `platform_tags`

See `docs/data.md` for column choices and omitted MITRE columns.

## Platform Filtering

`Applicable Platforms` from MITRE can narrow the larger 399-row DB. `prepare` supports:

- `--platform-filter none`: use every vulnerability in the DB.
- `--platform-filter auto`: detect tags from changed file paths and include generic rows.
- `--platform-filter specific`: include only rows matching detected/requested tags.

Auto-detected examples:

- `.py` -> `Python`
- `.js`, `.ts`, `.jsx`, `.tsx` -> `JavaScript`, `Web Based`
- `.c`, `.h`, `.cpp` -> `C`, `C++`, `Memory-Unsafe`
- `.java` -> `Java`
- `.php` -> `PHP`, `Web Based`, `Web Server`
- `.sql` -> `SQL`, `Database Server`

Use the larger DB with auto filtering:

```bash
python3 -m parallel_patch.cli prepare \
  --target tests/fixtures/change.diff \
  --vuln-db data/cwe_software_development.json \
  --platform-filter auto \
  --batch-size 10 \
  --output-dir parallel-patch-auto-run
```

Use specific-only filtering for a faster, narrower scan:

```bash
python3 -m parallel_patch.cli prepare \
  --target tests/fixtures/change.diff \
  --vuln-db data/cwe_software_development.json \
  --platform-filter specific \
  --batch-size 10 \
  --output-dir parallel-patch-specific-run
```

Add explicit platform tags when needed:

```bash
python3 -m parallel_patch.cli prepare \
  --target pr.diff \
  --vuln-db data/cwe_software_development.json \
  --platform-filter auto \
  --platform-tag "Web Based" \
  --platform-tag "Database Server" \
  --batch-size 10 \
  --output-dir parallel-patch-run
```

## Batch Size Guidance

- Top 25 DB: use `--batch-size 5`, yielding 5 agents.
- 399-row DB, no filtering: use `--batch-size 10` or `20`.
- 399-row DB, `specific` filtering: use `--batch-size 5` or `10`.
- For demos, smaller batches make the parallelism easier to see.

## Legacy Local Scan

There is still a deterministic local scan command:

```bash
python3 -m parallel_patch.cli scan \
  --target tests/fixtures/vulnerable_app \
  --vuln-db data/cwe_top25_sample.json \
  --batch-size 1 \
  --max-concurrent 2 \
  --output-dir parallel-patch-report \
  --format both
```

This does not use real Codex subagents. It is useful for testing schemas, report generation, and demos without API credentials.

## GitHub Actions Direction

The intended GitHub PR flow is:

```text
checkout repo
generate PR diff
run parallel_patch.cli prepare
run Codex/agent execution against generated prompts
run parallel_patch.cli aggregate
post report.md as a PR comment
upload report.json as an artifact
```

The stable artifact for integration is `scan_manifest.json`; it lists prompt paths, result paths, selected vulnerability IDs, platform-filter metadata, and batch count.

