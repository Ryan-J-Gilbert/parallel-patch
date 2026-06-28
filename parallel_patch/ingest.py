from __future__ import annotations

from pathlib import Path

from .models import SourceFile, SourceLine


DEFAULT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".ts",
    ".tsx",
}
DEFAULT_MAX_BYTES = 250_000


def ingest_target(target: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> list[SourceFile]:
    p = Path(target)
    if not p.exists():
        raise FileNotFoundError(f"target not found: {p}")
    if p.suffix.lower() in {".diff", ".patch"}:
        return ingest_diff(p)
    if p.is_file():
        return [_read_source_file(p, p.name, max_bytes)] if _is_scan_file(p, max_bytes) else []
    return [
        _read_source_file(path, str(path.relative_to(p)), max_bytes)
        for path in sorted(p.rglob("*"))
        if _is_scan_file(path, max_bytes)
    ]


def _is_scan_file(path: Path, max_bytes: int) -> bool:
    return path.is_file() and path.suffix.lower() in DEFAULT_EXTENSIONS and path.stat().st_size <= max_bytes


def _read_source_file(path: Path, display_path: str, max_bytes: int) -> SourceFile:
    text = path.read_text(errors="ignore")[:max_bytes]
    return SourceFile(
        path=display_path,
        lines=[SourceLine(number=i, text=line) for i, line in enumerate(text.splitlines(), start=1)],
    )


def ingest_diff(path: str | Path) -> list[SourceFile]:
    files: dict[str, list[SourceLine]] = {}
    current_file: str | None = None
    new_line = 0

    for raw in Path(path).read_text(errors="ignore").splitlines():
        if raw.startswith("+++ "):
            candidate = raw[4:].strip()
            current_file = candidate[2:] if candidate.startswith("b/") else candidate
            files.setdefault(current_file, [])
            continue
        if raw.startswith("@@"):
            new_line = _parse_hunk_new_start(raw)
            continue
        if current_file is None or raw.startswith("--- "):
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            files[current_file].append(SourceLine(number=max(new_line, 1), text=raw[1:]))
            new_line += 1
        elif raw.startswith(" ") or raw == "":
            new_line += 1

    return [SourceFile(path=file, lines=lines) for file, lines in files.items() if lines]


def _parse_hunk_new_start(line: str) -> int:
    marker = line.split(" +", 1)[1].split(" ", 1)[0]
    return int(marker.split(",", 1)[0].lstrip("+"))

