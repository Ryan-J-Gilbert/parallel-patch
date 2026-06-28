from __future__ import annotations

import csv
import json
from pathlib import Path

from pydantic import TypeAdapter

from .models import Vulnerability


_vuln_list_adapter = TypeAdapter(list[Vulnerability])


def load_vulnerabilities(path: str | Path) -> list[Vulnerability]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"vulnerability database not found: {p}")

    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text())
    elif p.suffix.lower() == ".csv":
        with p.open(newline="") as handle:
            data = list(csv.DictReader(handle))
    else:
        raise ValueError(f"unsupported vulnerability database format: {p.suffix}")

    return _vuln_list_adapter.validate_python(data)

