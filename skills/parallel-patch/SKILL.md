---
name: parallel-patch
description: Codex-native parallel vulnerability scanning for local codebases or PR diffs using generated subagent prompts, a vulnerability database, structured JSON findings, deduplication, and Markdown/JSON reports. Use when Codex needs to prepare or run a parallel-patch scan, spawn focused security-review subagents for CWE/CVE batches, or generate a PR-ready security findings report.
---

# parallel-patch

Use the repo-local `parallel_patch` Python package to prepare Codex subagent prompts from a local source tree or unified diff. Prefer the prompt/manifest workflow for real scans; use the legacy `scan` command only as a deterministic local demo.

## Workflow

1. Prefer `data/cwe_top25_mitre.json` for first real scans. Use `data/cwe_software_development.json` for larger platform-aware scans.
2. Prepare a scan run:

```bash
python -m parallel_patch.cli prepare --target ./pr.diff --vuln-db ./data/cwe_top25_mitre.json --batch-size 5 --output-dir ./parallel-patch-run
```

3. Read `parallel-patch-run/orchestrator.md`.
4. Spawn one Codex subagent per listed prompt. Each subagent must write only a JSON array to its assigned result path.
5. Aggregate results:

```bash
python -m parallel_patch.cli aggregate --manifest ./parallel-patch-run/scan_manifest.json --output-dir ./parallel-patch-run/report --format both
```

6. Inspect both generated report artifacts:
   - `report.json` for machine-readable findings
   - `report.md` for PR-comment-friendly output

## Notes

- `prepare` is the primary path for Codex-native parallelism.
- `aggregate` treats missing or malformed subagent result files as failed agents instead of failing the whole scan.
- The legacy `scan` command uses a deterministic local adapter, so it works without API keys and remains useful for tests and demos.
- For PR-style usage, pass a `.diff` or `.patch` file as `--target`; only added lines from changed hunks are scanned.

## Platform Filtering

Use platform filtering with the larger 399-row `data/cwe_software_development.json` database:

```bash
python -m parallel_patch.cli prepare --target ./pr.diff --vuln-db ./data/cwe_software_development.json --platform-filter auto --batch-size 10 --output-dir ./parallel-patch-run
```

Modes:

- `--platform-filter none`: use every vulnerability in the DB.
- `--platform-filter auto`: detect platform tags from changed file paths and include generic rows plus matching platform-specific rows.
- `--platform-filter specific`: include only matching platform-specific rows; faster but less comprehensive.
- `--platform-tag "Web Based"`: add an explicit tag when file-path detection misses framework/product context. Repeat as needed.
- `--specific-only`: with `auto`, exclude generic rows and behave like a narrow scan.

Common detected tags:

- `.py` -> `Python`
- `.js`, `.ts`, `.jsx`, `.tsx` -> `JavaScript`, `Web Based`
- `.c`, `.h`, `.cpp` -> `C`, `C++`, `Memory-Unsafe`
- `.java` -> `Java`
- `.php` -> `PHP`, `Web Based`, `Web Server`
- `.sql` -> `SQL`, `Database Server`

Batch guidance:

- Top 25 DB: use `--batch-size 5`.
- 399-row DB without filtering or with `auto`: use `--batch-size 10` or `20`.
- 399-row DB with `specific`: use `--batch-size 5` or `10`.

For detailed data-source and conversion notes, read `docs/data.md`.
