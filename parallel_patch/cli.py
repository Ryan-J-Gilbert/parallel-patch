from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from .orchestrator import scan_target
from .output import write_report
from .prompting import prepare_scan
from .results import aggregate_manifest_results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="parallel-patch")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a local path or unified diff")
    scan.add_argument("--target", required=True)
    scan.add_argument("--vuln-db", required=True)
    scan.add_argument("--batch-size", type=int, default=5)
    scan.add_argument("--max-concurrent", type=int, default=5)
    scan.add_argument("--output-dir", default="parallel-patch-report")
    scan.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    prepare = sub.add_parser("prepare", help="prepare Codex subagent prompts from a target and vulnerability DB")
    prepare.add_argument("--target", required=True)
    prepare.add_argument("--vuln-db", required=True)
    prepare.add_argument("--batch-size", type=int, default=5)
    prepare.add_argument("--output-dir", default="parallel-patch-run")
    prepare.add_argument("--platform-filter", choices=["none", "auto", "specific"], default="none")
    prepare.add_argument(
        "--platform-tag",
        action="append",
        default=[],
        help="Additional platform tag to select, such as Python, Web Based, C, or Memory-Unsafe. Repeat as needed.",
    )
    prepare.add_argument(
        "--specific-only",
        action="store_true",
        help="With --platform-filter auto, exclude generic Not Language-Specific / Not Technology-Specific rows.",
    )
    aggregate = sub.add_parser("aggregate", help="aggregate Codex subagent JSON results")
    aggregate.add_argument("--manifest", required=True)
    aggregate.add_argument("--output-dir", default="parallel-patch-report")
    aggregate.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        report = asyncio.run(
            scan_target(
                target=args.target,
                vuln_db=args.vuln_db,
                batch_size=args.batch_size,
                max_concurrent=args.max_concurrent,
            )
        )
        written = write_report(report, Path(args.output_dir), args.format)
        print(f"wrote {len(written)} report file(s):")
        for path in written:
            print(path)
    elif args.command == "prepare":
        manifest = prepare_scan(
            target=args.target,
            vuln_db=args.vuln_db,
            output_dir=args.output_dir,
            batch_size=args.batch_size,
            platform_filter=args.platform_filter,
            platform_tags=args.platform_tag,
            include_generic_platforms=not args.specific_only,
        )
        print(
            f"wrote scan manifest for {manifest.total_agents} agent(s) "
            f"({manifest.selected_vulnerabilities}/{manifest.total_vulnerabilities} vulnerabilities selected)"
        )
        if manifest.detected_platform_tags:
            print("detected platform tags: " + ", ".join(manifest.detected_platform_tags))
        print(Path(args.output_dir) / "scan_manifest.json")
        print(Path(args.output_dir) / "orchestrator.md")
    elif args.command == "aggregate":
        report = aggregate_manifest_results(args.manifest, args.output_dir, args.format)
        print(f"aggregated {len(report.findings)} finding(s) from {report.total_agents} agent(s)")
        print(Path(args.output_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
