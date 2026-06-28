#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


def main() -> int:
    args = parse_args()
    rows = read_rows(args.input)
    converted = [
        convert_row(row, rank=i, severity_strategy=args.severity_strategy, source=args.source)
        for i, row in enumerate(rows, start=1)
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(converted, indent=2) + "\n")
    print(f"wrote {len(converted)} CWE entries to {args.output}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert MITRE CWE view CSV files to parallel-patch JSON.")
    parser.add_argument("input", type=Path, help="MITRE CWE CSV file, such as 1435.csv or 699.csv")
    parser.add_argument("output", type=Path, help="Output JSON path")
    parser.add_argument(
        "--severity-strategy",
        choices=["top25-rank", "medium"],
        default="top25-rank",
        help="How to populate parallel-patch's required severity field.",
    )
    parser.add_argument(
        "--source",
        default="MITRE CWE CSV",
        help="Source label stored in each generated entry.",
    )
    return parser.parse_args()


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def convert_row(row: dict[str, str], rank: int, severity_strategy: str, source: str) -> dict[str, object]:
    cwe_id = row["CWE-ID"].strip()
    name = normalize_space(row["Name"])
    description = build_description(row)
    return {
        "id": f"CWE-{cwe_id}",
        "name": name,
        "severity": derive_severity(rank, severity_strategy),
        "description": description,
        "indicators": build_indicators(row),
        "source": source,
        "rank": rank,
        "status": normalize_space(row.get("Status", "")),
        "weakness_abstraction": normalize_space(row.get("Weakness Abstraction", "")),
        "applicable_platforms": normalize_space(row.get("Applicable Platforms", "")),
        "platform_tags": parse_platform_tags(row.get("Applicable Platforms", "")),
    }


def build_description(row: dict[str, str]) -> str:
    description = normalize_space(row.get("Description", ""))
    extended = normalize_space(row.get("Extended Description", ""))
    if extended:
        return f"{description} {truncate(extended, 600)}"
    return description


def build_indicators(row: dict[str, str]) -> list[str]:
    values: list[str] = []
    name = normalize_space(row.get("Name", ""))
    values.append(name)
    values.extend(re.findall(r"'([^']+)'", name))
    values.extend(extract_mitre_terms(row.get("Alternate Terms", "")))
    return dedupe([value for value in values if 3 <= len(value) <= 120])


def extract_mitre_terms(raw: str, key: str = "TERM") -> list[str]:
    if not raw:
        return []
    pattern = rf"{re.escape(key)}:([^:]+)"
    return [normalize_space(match) for match in re.findall(pattern, raw)]


def parse_platform_tags(raw: str) -> list[str]:
    values: list[str] = []
    for block in raw.split("::"):
        block = block.strip(":")
        if not block:
            continue
        parts = block.split(":")
        fields = {parts[i]: parts[i + 1] for i in range(0, len(parts) - 1, 2)}
        for key in (
            "LANGUAGE NAME",
            "LANGUAGE CLASS",
            "TECHNOLOGY NAME",
            "TECHNOLOGY CLASS",
            "OPERATING SYSTEM NAME",
            "OPERATING SYSTEM CLASS",
            "ARCHITECTURE NAME",
            "ARCHITECTURE CLASS",
        ):
            if key in fields:
                values.append(normalize_space(fields[key]))
    return dedupe(values)


def derive_severity(rank: int, strategy: str) -> str:
    if strategy == "medium":
        return "medium"
    if rank <= 5:
        return "critical"
    if rank <= 15:
        return "high"
    return "medium"


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "..."


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            output.append(value)
    return output[:8]


if __name__ == "__main__":
    raise SystemExit(main())
