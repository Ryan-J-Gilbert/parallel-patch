# parallel-patch: Parallel Agent-Based Vulnerability Scanner

## Overview

parallel-patch is a multi-agent system that parallelizes vulnerability scanning across a codebase or pull request. Rather than scanning sequentially for thousands of known vulnerabilities, it distributes the workload across specialized agents — each responsible for a small, focused subset of vulnerabilities — and aggregates their findings into a prioritized, actionable report.

---

## Core Concept

Given a database of ~1,000 known vulnerabilities, the system partitions them into batches (e.g., 100 agents × 10 vulnerabilities each). Each agent independently analyzes the target codebase for its assigned subset, returns structured findings, and the results are aggregated into a final summary report.

**Key advantages:**
- Parallelism dramatically reduces end-to-end scan time
- Each agent has a narrow, well-defined scope, reducing hallucination and improving precision
- The approach is modular — vulnerability sets and agent counts are configurable
- Works on both full codebases and targeted PR diffs

---

## System Architecture

```
Input: Codebase / PR diff
         │
         ▼
  Vulnerability DB (1,000 vulns)
         │
         ▼
  Partition into N batches of K vulns each
         │
    ┌────┴────┐
    ▼         ▼  ... (N agents in parallel)
 Agent 1   Agent 2
  [v1–v10] [v11–v20]
    │         │
    └────┬────┘
         ▼
  Aggregate all structured findings
         │
         ▼
  Summarization Agent (optional LLM pass)
         │
         ▼
  Final Report: prioritized, deduplicated findings
```

---

## Orchestrator Skill (Entry Point)

The system is kicked off by a single **Orchestrator Skill** — a Claude Code / Codex skill that serves as the top-level controller. When invoked, it reads the vulnerability database, partitions it into batches, and programmatically spawns all subagents. The user (or CI system) only ever interacts with this one entry point.

### Responsibilities

1. Load and parse the vulnerability database (CSV or JSON)
2. Chunk the list into batches of K vulnerabilities each
3. Ingest the target codebase or PR diff
4. Spawn N subagents in parallel, one per batch
5. Collect all results and pass them to the aggregation layer

### Skill Invocation

In Claude Code, the skill is invoked as a slash command or natural language trigger:

```
/scan --target ./my-repo --vuln-db vulns.csv --batch-size 10
```

Or via natural language in an agentic session:

```
Scan the current repository for vulnerabilities using the CWE database at ./data/cwe_top25.json
```

### Orchestrator Implementation

```python
import asyncio
import csv
import json
from pathlib import Path
from anthropic import AsyncAnthropic

client = AsyncAnthropic()

def load_vulnerabilities(path: str) -> list[dict]:
    """Load vulnerabilities from CSV or JSON."""
    p = Path(path)
    if p.suffix == ".json":
        return json.loads(p.read_text())
    elif p.suffix == ".csv":
        with open(p) as f:
            return list(csv.DictReader(f))
    raise ValueError(f"Unsupported format: {p.suffix}")

def partition(items: list, batch_size: int) -> list[list]:
    """Split a list into batches of batch_size."""
    return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]

def build_agent_prompt(vuln_batch: list[dict], codebase: str) -> str:
    vuln_list = "\n".join(
        f"- [{v['id']}] {v['name']}: {v['description']}"
        for v in vuln_batch
    )
    return AGENT_PROMPT_TEMPLATE.format(
        vulnerability_list=vuln_list,
        codebase=codebase
    )

async def run_agent(agent_id: int, vuln_batch: list[dict], codebase: str) -> dict:
    """Spawn a single subagent and return its findings."""
    prompt = build_agent_prompt(vuln_batch, codebase)
    try:
        response = await client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        findings = json.loads(response.content[0].text)
        return {
            "agent_id": agent_id,
            "vulnerability_batch": [v["id"] for v in vuln_batch],
            "findings": findings,
            "error": None
        }
    except Exception as e:
        return {
            "agent_id": agent_id,
            "vulnerability_batch": [v["id"] for v in vuln_batch],
            "findings": [],
            "error": str(e)
        }

async def orchestrate(vuln_db_path: str, codebase: str, batch_size: int = 10) -> list[dict]:
    """Main orchestrator: load vulns, partition, spawn all agents in parallel."""
    vulns = load_vulnerabilities(vuln_db_path)
    batches = partition(vulns, batch_size)

    print(f"Loaded {len(vulns)} vulnerabilities → {len(batches)} agents (batch size: {batch_size})")

    tasks = [
        run_agent(agent_id=i, vuln_batch=batch, codebase=codebase)
        for i, batch in enumerate(batches)
    ]

    # All agents run concurrently
    results = await asyncio.gather(*tasks)
    return list(results)
```

### Vulnerability Database Format

The orchestrator accepts either CSV or JSON. Both formats must include at minimum:

**CSV (`vulns.csv`)**
```csv
id,name,severity,description
CWE-89,SQL Injection,critical,"User input concatenated directly into SQL queries without parameterization."
CWE-79,Cross-Site Scripting,high,"Unsanitized user input rendered in HTML output."
CWE-22,Path Traversal,high,"File paths constructed from user input without canonicalization."
```

**JSON (`vulns.json`)**
```json
[
  {
    "id": "CWE-89",
    "name": "SQL Injection",
    "severity": "critical",
    "description": "User input concatenated directly into SQL queries without parameterization.",
    "indicators": ["raw SQL string formatting", "f-string queries", "string concatenation with user input"]
  }
]
```

The optional `indicators` field (JSON only) gives the agent concrete patterns to search for and meaningfully improves recall.

### Claude Code Skill Definition (`CLAUDE.md` entry)

To register this as a Claude Code skill, add the following to the project's `CLAUDE.md`:

```markdown
## /scan

Scan a codebase for security vulnerabilities using a parallel agent swarm.

**Usage:** `/scan --target <path|url> --vuln-db <path> [--batch-size N] [--output <json|markdown>]`

**What it does:**
1. Loads the vulnerability database from `--vuln-db` (CSV or JSON)
2. Partitions vulnerabilities into batches of `--batch-size` (default: 10)
3. Spawns one subagent per batch, all running in parallel
4. Aggregates and deduplicates findings
5. Returns a prioritized report in the specified output format

**Example:**
/scan --target ./src --vuln-db ./data/cwe_top25.json --batch-size 10 --output markdown
```

### Concurrency & Rate Limit Considerations

Running 100 agents simultaneously against the Anthropic API will hit rate limits. The orchestrator should implement a **semaphore** to cap concurrent requests:

```python
async def orchestrate_with_concurrency_limit(
    vuln_db_path: str,
    codebase: str,
    batch_size: int = 10,
    max_concurrent: int = 20   # Tune based on your API tier
) -> list[dict]:
    vulns = load_vulnerabilities(vuln_db_path)
    batches = partition(vulns, batch_size)
    semaphore = asyncio.Semaphore(max_concurrent)

    async def run_with_limit(agent_id, batch):
        async with semaphore:
            return await run_agent(agent_id, batch, codebase)

    tasks = [run_with_limit(i, batch) for i, batch in enumerate(batches)]
    return list(await asyncio.gather(*tasks))
```

Recommended starting values by API tier:

| Tier | `max_concurrent` | Expected latency (100 agents) |
|------|-----------------|-------------------------------|
| Free / Tier 1 | 5 | ~3–5 min |
| Tier 2 | 20 | ~45–90 sec |
| Tier 3+ | 50 | ~20–40 sec |

---

## Agent Prompt Template

Each agent receives the full codebase (or diff) and its assigned vulnerability subset:

```
You are a security analysis agent. Your task is to scan the provided codebase for the specific vulnerabilities listed below. Do not report on any vulnerabilities outside this list.

## Vulnerabilities to Detect

{vulnerability_list}

Each entry includes:
- Vulnerability ID (e.g., CWE-89)
- Name (e.g., SQL Injection)
- Description and indicators to look for

## Instructions

1. Carefully review the provided code.
2. For each vulnerability in your list, determine if it is present.
3. If present, record the exact location and a brief explanation.
4. If not present, do not include it in your output.
5. Return ONLY a valid JSON array conforming to the schema below. No preamble or explanation.

## Output Schema

[
  {
    "vulnerability_id": "CWE-89",
    "vulnerability_name": "SQL Injection",
    "file": "src/db/queries.py",
    "line_start": 42,
    "line_end": 45,
    "severity": "critical",
    "confidence": "high",
    "description": "User-controlled input passed directly to a raw SQL query without parameterization.",
    "suggested_fix": "Use parameterized queries or an ORM."
  }
]
```

---

## Structured Output Schema

```python
class VulnerabilityFinding(BaseModel):
    vulnerability_id: str        # e.g., "CWE-89", "OWASP-A03"
    vulnerability_name: str      # Human-readable name
    file: str                    # Relative path to affected file
    line_start: int              # Starting line number
    line_end: Optional[int]      # Ending line number (if range)
    severity: Literal["critical", "high", "medium", "low", "informational"]
    confidence: Literal["high", "medium", "low"]
    description: str             # What the issue is and why it's dangerous
    suggested_fix: Optional[str] # Recommended remediation

class AgentResult(BaseModel):
    agent_id: int
    vulnerability_batch: List[str]   # IDs of vulns this agent was assigned
    findings: List[VulnerabilityFinding]
    error: Optional[str]             # Capture any agent-level failures

class ScanReport(BaseModel):
    scan_id: str
    target: str                       # Repo URL, PR number, or path
    timestamp: datetime
    total_agents: int
    findings: List[VulnerabilityFinding]
    summary: Optional[str]            # LLM-generated summary
```

---

## Aggregation & Final Report

After all agents complete:

1. **Collect** all `AgentResult` objects, handling any agent failures gracefully
2. **Deduplicate** findings that reference the same file/line (multiple agents may flag the same issue if vulnerability descriptions overlap)
3. **Sort** by severity (critical → high → medium → low)
4. **Optional summarization pass**: send aggregated findings to an LLM to generate a human-readable executive summary highlighting the most critical issues, patterns, and recommended remediation priorities
5. **Output formats**: JSON (machine-readable), Markdown (PR comment), or HTML report

---

## Vulnerability Database

### Sources to Evaluate

| Source | Description | Format |
|--------|-------------|--------|
| **NVD (National Vulnerability Database)** | NIST-maintained, CVE-linked | JSON API |
| **CWE List** | MITRE's weakness taxonomy (~900 entries) | XML/JSON |
| **OWASP Top 10** | Web application security risks | Curated list |
| **Semgrep Registry** | Community-contributed patterns | YAML rules |
| **CodeQL queries** | GitHub's semantic analysis queries | QL files |
| **OSV (Open Source Vulnerabilities)** | Package-level vulnerability DB | JSON API |

### Recommendation

Start with the **CWE Top 25 Most Dangerous Software Weaknesses** (~25 entries) for the initial eval, then expand to the full CWE list (~900 entries) and OWASP. This gives a well-structured, well-documented set with clear detection criteria.

Each vulnerability in the agent prompt should include:
- CWE/CVE ID
- Name
- 2–3 sentence description of what to look for
- Example of vulnerable pattern (optional but improves precision)

---

## Evaluation Framework

### Primary Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| **Precision** | Findings that are true positives / total findings | > 80% |
| **Recall** | True positives found / total true positives in benchmark | > 70% |
| **F1 Score** | Harmonic mean of precision and recall | Maximize |
| **Latency** | Time from submission to final report | < 60s for a typical PR |
| **Cost per scan** | Total token cost across all agents | Minimize |

### Evaluation Dataset Options

- **OWASP WebGoat** — intentionally vulnerable Java app
- **DVWA (Damn Vulnerable Web Application)** — PHP/MySQL test bed
- **Juliet Test Suite** — NIST's synthetic benchmark with 118 CWE types
- **SecBench / SWE-bench Security** — real-world security patches as ground truth

### Eval Scenarios

1. **Baseline**: Single-agent scan vs. swarm scan — compare precision/recall
2. **Scale**: How does performance change from 10 → 100 → 500 agents?
3. **Cost efficiency**: Swarm with cheaper model (Haiku) vs. single pass with larger model (Sonnet/Opus)
4. **Noise tolerance**: Does agent specialization reduce false positives?

---

## Implementation Plan

### Phase 1: Foundation

- [ ] **1.1** Select and download vulnerability database (CWE list recommended as starting point)
- [ ] **1.2** Write preprocessing script to clean, normalize, and structure vulnerability entries
- [ ] **1.3** Implement partitioning logic: split N vulnerabilities into batches of K
- [ ] **1.4** Write code ingestion pipeline: accept GitHub repo URL, local path, or PR diff
- [ ] **1.5** Define and finalize `VulnerabilityFinding` and `ScanReport` Pydantic schemas

### Phase 2: Agent Implementation

- [ ] **2.1** Implement single-agent scan with structured output (validate schema compliance)
- [ ] **2.2** Finalize and test the agent prompt template; iterate on false positive rate
- [ ] **2.3** Add confidence scoring logic to the prompt (instruct agent to rate certainty)
- [ ] **2.4** Implement parallel agent orchestration (asyncio + concurrent API calls)
- [ ] **2.5** Add retry logic and error handling for agent failures
- [ ] **2.6** Implement in **Claude Code / Codex** (migrate to custom async framework if needed for parallelism control)

### Phase 3: Aggregation & Output

- [ ] **3.1** Build aggregation layer: collect all agent outputs, handle partial failures
- [ ] **3.2** Implement deduplication logic (same file + overlapping line range → merge)
- [ ] **3.3** Implement severity-based sorting and grouping
- [ ] **3.4** Add optional summarization agent: LLM call to produce executive summary
- [ ] **3.5** Build output formatters: JSON, Markdown (for PR comments), CLI table

### Phase 4: Evaluation

- [ ] **4.1** Set up evaluation harness against chosen benchmark (Juliet or WebGoat recommended)
- [ ] **4.2** Implement precision/recall/F1 calculation
- [ ] **4.3** Run baseline: single-agent vs. swarm — document results
- [ ] **4.4** Run cost/performance tradeoff experiments (model size vs. agent count)
- [ ] **4.5** Document findings and tune partition size / prompt based on results

### Phase 5: Polish (if time allows)

- [ ] **5.1** GitHub PR integration: post findings as PR review comments
- [ ] **5.2** CI/CD integration: GitHub Action or pre-commit hook
- [ ] **5.3** Web UI or CLI dashboard for scan results
- [ ] **5.4** Incremental scanning: only scan changed files in a PR diff

---

## Open Questions & Design Decisions

| Question | Options | Recommendation |
|----------|---------|----------------|
| How many vulnerabilities per agent? | 5 / 10 / 20 | Start with 10; tune based on precision |
| Model for agents? | Haiku, Sonnet, Opus | Sonnet for eval; compare Haiku for cost |
| Parallel execution framework? | asyncio, Codex, LangGraph, custom | asyncio first; migrate if needed |
| How to handle large codebases? | Chunking, file filtering, diff-only | Start with diff-only for PRs |
| Dedup strategy? | Exact match, fuzzy line overlap, semantic | Exact file + line overlap to start |
| Final summary model? | Same as agents, or larger? | One size up from agents (e.g., Sonnet if agents = Haiku) |

---

## Hackathon Scope (MVP)

For a hackathon demo, prioritize:

1. ✅ Vulnerability DB: CWE Top 25 (or subset)
2. ✅ Parallel agent orchestration: 10–25 agents
3. ✅ Structured output with file + line number
4. ✅ Aggregated final report in Markdown
5. ✅ Eval on one known-vulnerable repo (e.g., WebGoat or DVWA)
6. ⬜ GitHub PR integration (stretch)
7. ⬜ Web UI (stretch)
