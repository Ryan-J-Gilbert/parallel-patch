import asyncio
import csv
import json
import tempfile
import time
import unittest
from pathlib import Path

from pydantic import ValidationError

from parallel_patch.adapters import ScanAdapter, parse_findings_json
from parallel_patch.aggregate import aggregate_results
from parallel_patch.db import load_vulnerabilities
from parallel_patch.ingest import ingest_diff, ingest_target
from parallel_patch.models import AgentResult, Vulnerability, VulnerabilityFinding
from parallel_patch.orchestrator import scan_target
from parallel_patch.output import write_report
from parallel_patch.partition import partition
from parallel_patch.platforms import detect_platform_tags, filter_vulnerabilities_by_platform
from parallel_patch.prompting import prepare_scan
from parallel_patch.results import aggregate_manifest_results, load_manifest
from scripts.convert_cwe_csv import convert_row, parse_platform_tags


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DB = ROOT / "data" / "cwe_top25_sample.json"
FIXTURE_APP = ROOT / "tests" / "fixtures" / "vulnerable_app"


class FailingOnceAdapter(ScanAdapter):
    def __init__(self):
        self.calls = 0

    async def scan(self, agent_id, vulnerability_batch, sources):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("temporary failure")
        return []


class SlowTrackingAdapter(ScanAdapter):
    def __init__(self):
        self.current = 0
        self.maximum = 0

    async def scan(self, agent_id, vulnerability_batch, sources):
        self.current += 1
        self.maximum = max(self.maximum, self.current)
        await asyncio.sleep(0.02)
        self.current -= 1
        return []


class ParallelPatchTests(unittest.TestCase):
    def test_load_json_and_csv_vulnerability_db(self):
        vulnerabilities = load_vulnerabilities(SAMPLE_DB)
        self.assertEqual(["CWE-79", "CWE-89", "CWE-22"], [v.id for v in vulnerabilities])

        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "vulns.csv"
            with csv_path.open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["id", "name", "severity", "description"])
                writer.writeheader()
                writer.writerow(
                    {
                        "id": "CWE-20",
                        "name": "Input Validation",
                        "severity": "medium",
                        "description": "Missing validation.",
                    }
                )
            self.assertEqual("CWE-20", load_vulnerabilities(csv_path)[0].id)

    def test_rejects_malformed_vulnerability_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "bad.json"
            bad_path.write_text(json.dumps([{"id": "", "name": "Bad", "severity": "unknown", "description": ""}]))
            with self.assertRaises(ValidationError):
                load_vulnerabilities(bad_path)

    def test_partition_validates_batch_size(self):
        self.assertEqual([[1, 2], [3]], partition([1, 2, 3], 2))
        with self.assertRaises(ValueError):
            partition([1], 0)

    def test_parse_and_validate_agent_output(self):
        raw = json.dumps(
            [
                {
                    "vulnerability_id": "CWE-89",
                    "vulnerability_name": "SQL Injection",
                    "file": "app.py",
                    "line_start": 3,
                    "line_end": 3,
                    "severity": "critical",
                    "confidence": "high",
                    "description": "Raw SQL.",
                    "suggested_fix": "Use parameters.",
                }
            ]
        )
        self.assertEqual("CWE-89", parse_findings_json(raw)[0].vulnerability_id)

    def test_deduplicates_and_sorts_findings(self):
        low = VulnerabilityFinding(
            vulnerability_id="CWE-79",
            vulnerability_name="XSS",
            file="b.py",
            line_start=10,
            line_end=10,
            severity="high",
            confidence="low",
            description="A",
        )
        high = VulnerabilityFinding(
            vulnerability_id="CWE-89",
            vulnerability_name="SQLi",
            file="a.py",
            line_start=1,
            line_end=2,
            severity="critical",
            confidence="medium",
            description="B",
        )
        duplicate = high.model_copy(update={"line_start": 2, "line_end": 4, "confidence": "high"})
        findings, failed = aggregate_results(
            [
                AgentResult(agent_id=1, vulnerability_batch=["CWE-79"], findings=[low]),
                AgentResult(agent_id=2, vulnerability_batch=["CWE-89"], findings=[high, duplicate]),
                AgentResult(agent_id=3, vulnerability_batch=[], findings=[], error="boom"),
            ]
        )
        self.assertEqual(1, failed)
        self.assertEqual(["CWE-89", "CWE-79"], [f.vulnerability_id for f in findings])
        self.assertEqual((1, 4, "high"), (findings[0].line_start, findings[0].line_end, findings[0].confidence))

    def test_ingests_directory_and_diff(self):
        self.assertEqual(["app.py"], [source.path for source in ingest_target(FIXTURE_APP)])
        diff_sources = ingest_diff(ROOT / "tests" / "fixtures" / "change.diff")
        self.assertEqual("app.py", diff_sources[0].path)
        self.assertEqual([2, 3], [line.number for line in diff_sources[0].lines])

    def test_scan_writes_json_and_markdown_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = asyncio.run(scan_target(FIXTURE_APP, SAMPLE_DB, batch_size=1, max_concurrent=2))
            written = write_report(report, tmp, "both")
            names = sorted(path.name for path in written)
            self.assertEqual(["report.json", "report.md"], names)
            self.assertTrue(report.findings)

    def test_failed_agent_does_not_fail_scan(self):
        report = asyncio.run(
            scan_target(FIXTURE_APP, SAMPLE_DB, batch_size=3, max_concurrent=1, adapter=FailingOnceAdapter())
        )
        self.assertEqual(0, report.failed_agents)

    def test_max_concurrent_is_respected(self):
        adapter = SlowTrackingAdapter()
        many_vulns = [
            Vulnerability(id=f"CWE-{i}", name=f"Vuln {i}", severity="low", description="test", indicators=["never"])
            for i in range(8)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "db.json"
            db_path.write_text(json.dumps([v.model_dump() for v in many_vulns]))
            asyncio.run(scan_target(FIXTURE_APP, db_path, batch_size=1, max_concurrent=2, adapter=adapter))
        self.assertLessEqual(adapter.maximum, 2)

    def test_prepare_writes_prompts_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = prepare_scan(ROOT / "tests" / "fixtures" / "change.diff", SAMPLE_DB, tmp, batch_size=2)
            manifest_path = Path(tmp) / "scan_manifest.json"
            orchestrator_path = Path(tmp) / "orchestrator.md"

            self.assertTrue(manifest_path.exists())
            self.assertTrue(orchestrator_path.exists())
            self.assertEqual(2, manifest.total_agents)
            self.assertEqual(2, len(list((Path(tmp) / "prompts").glob("agent-*.md"))))
            prompt = Path(manifest.batches[0].prompt_path).read_text()
            self.assertIn("Return only a JSON array", prompt)
            self.assertIn("CWE-79", prompt)
            self.assertIn("app.py", prompt)

            loaded = load_manifest(manifest_path)
            self.assertEqual(manifest.scan_id, loaded.scan_id)
            self.assertEqual(["Python"], manifest.detected_platform_tags)

    def test_aggregate_manifest_results_handles_missing_and_valid_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = prepare_scan(ROOT / "tests" / "fixtures" / "change.diff", SAMPLE_DB, tmp, batch_size=2)
            Path(manifest.batches[0].result_path).write_text(
                json.dumps(
                    [
                        {
                            "vulnerability_id": "CWE-89",
                            "vulnerability_name": "SQL Injection",
                            "file": "app.py",
                            "line_start": 2,
                            "line_end": 2,
                            "severity": "critical",
                            "confidence": "high",
                            "description": "Interpolated SQL in changed line.",
                            "suggested_fix": "Use query parameters.",
                        }
                    ]
                )
            )

            report = aggregate_manifest_results(Path(tmp) / "scan_manifest.json", Path(tmp) / "report", "both")
            self.assertEqual(1, len(report.findings))
            self.assertEqual(1, report.failed_agents)
            self.assertTrue((Path(tmp) / "report" / "report.json").exists())
            self.assertTrue((Path(tmp) / "report" / "report.md").exists())

    def test_converts_mitre_cwe_row_to_parallel_patch_json_shape(self):
        row = {
            "CWE-ID": "89",
            "Name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "Weakness Abstraction": "Base",
            "Status": "Stable",
            "Description": "User input is used in SQL commands.",
            "Extended Description": "Attackers may modify query structure.",
            "Alternate Terms": "::TERM:SQLi:DESCRIPTION:Common abbreviation::",
            "Applicable Platforms": "::LANGUAGE NAME:SQL:LANGUAGE PREVALENCE:Often::TECHNOLOGY NAME:Database Server:TECHNOLOGY PREVALENCE:Undetermined::",
            "Taxonomy Mappings": "::TAXONOMY NAME:OWASP:ENTRY NAME:Injection::",
        }

        converted = convert_row(row, rank=6, severity_strategy="top25-rank", source="test")

        self.assertEqual("CWE-89", converted["id"])
        self.assertEqual("high", converted["severity"])
        self.assertIn("SQL Injection", converted["indicators"])
        self.assertIn("SQLi", converted["indicators"])
        self.assertNotIn("Injection", converted["indicators"])
        self.assertEqual(["SQL", "Database Server"], converted["platform_tags"])
        self.assertEqual(6, converted["rank"])

    def test_parse_platform_tags_extracts_structured_mitre_values(self):
        raw = (
            "::LANGUAGE CLASS:Not Language-Specific:LANGUAGE PREVALENCE:Undetermined::"
            "TECHNOLOGY CLASS:Web Based:TECHNOLOGY PREVALENCE:Often::"
            "LANGUAGE NAME:JavaScript:LANGUAGE PREVALENCE:Often::"
        )

        self.assertEqual(["Not Language-Specific", "Web Based", "JavaScript"], parse_platform_tags(raw))

    def test_platform_filtering_can_include_or_exclude_generic_rows(self):
        generic = Vulnerability(
            id="CWE-20",
            name="Input Validation",
            severity="medium",
            description="Generic",
            platform_tags=["Not Language-Specific"],
        )
        python = Vulnerability(
            id="CWE-915",
            name="Python dynamic attribute modification",
            severity="medium",
            description="Python",
            platform_tags=["Python"],
        )
        c = Vulnerability(
            id="CWE-120",
            name="Buffer overflow",
            severity="medium",
            description="C",
            platform_tags=["C", "Memory-Unsafe"],
        )

        auto = filter_vulnerabilities_by_platform([generic, python, c], "auto", ["Python"])
        specific = filter_vulnerabilities_by_platform([generic, python, c], "specific", ["Python"])

        self.assertEqual(["CWE-20", "CWE-915"], [v.id for v in auto])
        self.assertEqual(["CWE-915"], [v.id for v in specific])

    def test_prepare_can_filter_by_detected_platform(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "db.json"
            db_path.write_text(
                json.dumps(
                    [
                        {
                            "id": "CWE-20",
                            "name": "Generic",
                            "severity": "medium",
                            "description": "Generic",
                            "platform_tags": ["Not Language-Specific"],
                        },
                        {
                            "id": "CWE-915",
                            "name": "Python issue",
                            "severity": "medium",
                            "description": "Python",
                            "platform_tags": ["Python"],
                        },
                        {
                            "id": "CWE-120",
                            "name": "C issue",
                            "severity": "medium",
                            "description": "C",
                            "platform_tags": ["C", "Memory-Unsafe"],
                        },
                    ]
                )
            )

            manifest = prepare_scan(
                FIXTURE_APP,
                db_path,
                tmp,
                batch_size=10,
                platform_filter="auto",
            )

            self.assertEqual(["Python"], detect_platform_tags(ingest_target(FIXTURE_APP)))
            self.assertEqual(2, manifest.selected_vulnerabilities)
            prompt = Path(manifest.batches[0].prompt_path).read_text()
            self.assertIn("CWE-20", prompt)
            self.assertIn("CWE-915", prompt)
            self.assertNotIn("CWE-120", prompt)


if __name__ == "__main__":
    unittest.main()
