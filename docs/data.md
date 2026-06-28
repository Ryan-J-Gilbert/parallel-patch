# Data Sources and Conversion

`parallel-patch` consumes a compact JSON or CSV vulnerability database with these required fields:

- `id`
- `name`
- `severity`
- `description`
- optional `indicators`

MITRE CWE CSV files contain much richer data than the prompt generator needs. Keep the raw MITRE download outside the repo and generate a compact JSON file for scans.

## Current Source Files

The local downloaded files inspected during setup were:

- `/Users/ryan/Downloads/1435.csv`: MITRE CWE Top 25 view, 25 rows.
- `/Users/ryan/Downloads/699.csv`: MITRE software development CWE view, 399 rows.

Use `1435.csv` for the first real scan database. Use `699.csv` later when the batching and prompt-size tradeoffs are tuned.

## Conversion Command

Generate the Top 25 JSON:

```bash
python3 scripts/convert_cwe_csv.py \
  /Users/ryan/Downloads/1435.csv \
  data/cwe_top25_mitre.json \
  --source "MITRE CWE Top 25"
```

For the larger software-development view, use a neutral severity default:

```bash
python3 scripts/convert_cwe_csv.py \
  /Users/ryan/Downloads/699.csv \
  data/cwe_software_development.json \
  --severity-strategy medium \
  --source "MITRE CWE Software Development View"
```

The repository currently includes generated JSON outputs for both commands:

- `data/cwe_top25_mitre.json`
- `data/cwe_software_development.json`

## Column Mapping

Kept:

- `CWE-ID` -> `id`, with `CWE-` prefix.
- `Name` -> `name`.
- `Description` plus a truncated `Extended Description` -> `description`.
- `Name`, quoted aliases from `Name`, and `Alternate Terms` -> `indicators`.
- Row number -> `rank`.
- `Status` and `Weakness Abstraction` are retained as extra metadata.
- `Applicable Platforms` -> raw `applicable_platforms` plus parsed `platform_tags`.

Not used in prompts yet:

- `Related Weaknesses`
- `Weakness Ordinalities`
- `Applicable Platforms`
- `Modes Of Introduction`
- `Common Consequences`
- `Detection Methods`
- `Potential Mitigations`
- `Observed Examples`
- `Taxonomy Mappings`
- `Related Attack Patterns`
- `Notes`

Those columns are valuable later, but they are very large and can bloat every subagent prompt. Add them selectively only when a prompt design needs them.

## Applicable Platforms

`Applicable Platforms` is a structured MITRE field. Example:

```text
::LANGUAGE NAME:Python:LANGUAGE PREVALENCE:Undetermined::
::TECHNOLOGY CLASS:Web Based:TECHNOLOGY PREVALENCE:Often::
```

The converter extracts the platform values into `platform_tags`, such as:

```json
["Python", "Web Based"]
```

The larger `699.csv` file has 399 rows, 100 distinct raw `Applicable Platforms` strings, and these useful parsed row counts:

```text
Not Language-Specific: 331
Not Technology-Specific: 64
Web Based: 19
Web Server: 16
Database Server: 4
C: 53
C++: 51
Memory-Unsafe: 15
Java: 26
JavaScript: 4
Python: 5
PHP: 12
Mobile: 12
Cloud Computing: 6
ICS/OT: 18
```

Because generic rows dominate, do not use platform data as a strict filter by default. Prefer:

```text
selected CWEs = generic platform rows + rows matching detected/requested platform tags
```

Use `--platform-filter specific` only for fast exploratory scans where missing generic weaknesses is acceptable.

For the current Python diff fixture, the 399-row DB produces:

```text
--platform-filter auto:     342/399 selected, 35 agents at batch size 10
--platform-filter specific:   5/399 selected,  1 agent  at batch size 10
```

## Severity Defaults

MITRE CWE Top 25 rows do not include the `severity` field required by `parallel-patch`, so the converter derives it from rank:

- Rank 1-5: `critical`
- Rank 6-15: `high`
- Rank 16-25: `medium`

For non-ranked views such as `699.csv`, prefer `--severity-strategy medium` until there is a better scoring source.

## Batch Size Guidance

For `1435.csv`:

- 25 rows total.
- Start with `--batch-size 5`, which creates 5 subagents.
- Use `--batch-size 2` for local demos when you want more visibly parallel work.

For `699.csv`:

- 399 rows total in the downloaded file.
- Start with `--batch-size 10`, which creates about 40 subagents.
- Use `--batch-size 20` to reduce orchestration overhead.
- Avoid putting all 399 entries in one prompt; it will be noisy and expensive.
- With `--platform-filter auto`, generic rows remain included, so common web/Python/JavaScript patches may still select hundreds of rows.
- With `--platform-filter specific`, only matching platform-specific rows are included; this is faster but less comprehensive.

## Platform-Aware Prepare Examples

Auto-detect platforms from changed files and include generic rows:

```bash
python3 -m parallel_patch.cli prepare \
  --target tests/fixtures/change.diff \
  --vuln-db data/cwe_software_development.json \
  --platform-filter auto \
  --batch-size 10 \
  --output-dir parallel-patch-run
```

Only include platform-specific matches:

```bash
python3 -m parallel_patch.cli prepare \
  --target tests/fixtures/change.diff \
  --vuln-db data/cwe_software_development.json \
  --platform-filter specific \
  --batch-size 10 \
  --output-dir parallel-patch-specific-run
```

Add explicit tags when auto-detection misses framework context:

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
