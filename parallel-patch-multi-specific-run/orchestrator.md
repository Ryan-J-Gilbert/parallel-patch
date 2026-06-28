# parallel-patch Orchestrator

Spawn one Codex subagent per prompt listed below. Each subagent should read its prompt, analyze independently, and write only its JSON array result to the matching result path.

- Scan ID: `f451c2fe-42e0-4a89-a23d-c90374139490`
- Target: `tests/fixtures/multi_surface.diff`
- Vulnerability DB: `data/cwe_software_development.json`
- Platform filter: `specific`
- Detected platform tags: C, Database Server, JavaScript, Memory-Unsafe, Python, SQL, Web Based
- Requested platform tags: none
- Vulnerabilities selected: 81/399
- Total agents: 9

## Agent Work Items

- Agent 0: prompt `parallel-patch-multi-specific-run/prompts/agent-0.md`, result `parallel-patch-multi-specific-run/results/agent-0.json`, vulnerabilities CWE-79, CWE-89, CWE-90, CWE-120, CWE-124, CWE-125, CWE-128, CWE-130, CWE-131, CWE-134
- Agent 1: prompt `parallel-patch-multi-specific-run/prompts/agent-1.md`, result `parallel-patch-multi-specific-run/results/agent-1.json`, vulnerabilities CWE-135, CWE-170, CWE-190, CWE-191, CWE-193, CWE-242, CWE-243, CWE-295, CWE-346, CWE-364
- Agent 2: prompt `parallel-patch-multi-specific-run/prompts/agent-2.md`, result `parallel-patch-multi-specific-run/results/agent-2.json`, vulnerabilities CWE-366, CWE-374, CWE-375, CWE-396, CWE-397, CWE-403, CWE-425, CWE-444, CWE-463, CWE-464
- Agent 3: prompt `parallel-patch-multi-specific-run/prompts/agent-3.md`, result `parallel-patch-multi-specific-run/results/agent-3.json`, vulnerabilities CWE-466, CWE-468, CWE-469, CWE-472, CWE-474, CWE-476, CWE-478, CWE-480, CWE-483, CWE-484
- Agent 4: prompt `parallel-patch-multi-specific-run/prompts/agent-4.md`, result `parallel-patch-multi-specific-run/results/agent-4.json`, vulnerabilities CWE-497, CWE-502, CWE-549, CWE-551, CWE-562, CWE-587, CWE-601, CWE-611, CWE-613, CWE-617
- Agent 5: prompt `parallel-patch-multi-specific-run/prompts/agent-5.md`, result `parallel-patch-multi-specific-run/results/agent-5.json`, vulnerabilities CWE-618, CWE-619, CWE-663, CWE-676, CWE-681, CWE-698, CWE-733, CWE-763, CWE-783, CWE-786
- Agent 6: prompt `parallel-patch-multi-specific-run/prompts/agent-6.md`, result `parallel-patch-multi-specific-run/results/agent-6.json`, vulnerabilities CWE-787, CWE-788, CWE-805, CWE-807, CWE-822, CWE-823, CWE-824, CWE-825, CWE-837, CWE-839
- Agent 7: prompt `parallel-patch-multi-specific-run/prompts/agent-7.md`, result `parallel-patch-multi-specific-run/results/agent-7.json`, vulnerabilities CWE-843, CWE-910, CWE-911, CWE-915, CWE-918, CWE-1007, CWE-1021, CWE-1024, CWE-1073, CWE-1335
- Agent 8: prompt `parallel-patch-multi-specific-run/prompts/agent-8.md`, result `parallel-patch-multi-specific-run/results/agent-8.json`, vulnerabilities CWE-1341

After all result files exist, aggregate them with:

```bash
python -m parallel_patch.cli aggregate --manifest parallel-patch-multi-specific-run/scan_manifest.json --output-dir parallel-patch-multi-specific-run/report --format both
```
