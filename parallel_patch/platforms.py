from __future__ import annotations

from pathlib import Path

from .models import SourceFile, Vulnerability


GENERIC_PLATFORM_TAGS = {
    "Not Language-Specific",
    "Not Technology-Specific",
    "Not OS-Specific",
    "Not Architecture-Specific",
}


EXTENSION_TAGS = {
    ".c": {"C", "Memory-Unsafe"},
    ".cc": {"C++", "Memory-Unsafe"},
    ".cpp": {"C++", "Memory-Unsafe"},
    ".cxx": {"C++", "Memory-Unsafe"},
    ".h": {"C", "C++", "Memory-Unsafe"},
    ".hpp": {"C++", "Memory-Unsafe"},
    ".java": {"Java"},
    ".js": {"JavaScript", "Web Based"},
    ".jsx": {"JavaScript", "Web Based"},
    ".ts": {"JavaScript", "Web Based"},
    ".tsx": {"JavaScript", "Web Based"},
    ".py": {"Python"},
    ".php": {"PHP", "Web Based", "Web Server"},
    ".rb": {"Ruby"},
    ".rs": {"Rust"},
    ".go": {"Go"},
    ".sql": {"SQL", "Database Server"},
}

SPECIAL_FILE_TAGS = {
    "package.json": {"JavaScript", "Web Based"},
    "package-lock.json": {"JavaScript", "Web Based"},
    "yarn.lock": {"JavaScript", "Web Based"},
    "pnpm-lock.yaml": {"JavaScript", "Web Based"},
    "requirements.txt": {"Python"},
    "pyproject.toml": {"Python"},
    "poetry.lock": {"Python"},
    "pipfile": {"Python"},
    "go.mod": {"Go"},
    "go.sum": {"Go"},
    "pom.xml": {"Java"},
    "build.gradle": {"Java"},
    "composer.json": {"PHP", "Web Based"},
    "gemfile": {"Ruby"},
    "cargo.toml": {"Rust"},
}


def detect_platform_tags(sources: list[SourceFile]) -> list[str]:
    tags: set[str] = set()
    for source in sources:
        path = Path(source.path.lower())
        tags.update(SPECIAL_FILE_TAGS.get(path.name, set()))
        tags.update(EXTENSION_TAGS.get(path.suffix, set()))
    return sorted(tags)


def filter_vulnerabilities_by_platform(
    vulnerabilities: list[Vulnerability],
    mode: str,
    detected_tags: list[str],
    requested_tags: list[str] | None = None,
    include_generic: bool = True,
) -> list[Vulnerability]:
    if mode == "none":
        return vulnerabilities
    if mode not in {"auto", "specific"}:
        raise ValueError("platform filter must be one of: none, auto, specific")

    selected_tags = {tag.casefold() for tag in detected_tags}
    selected_tags.update(tag.casefold() for tag in (requested_tags or []))
    if not selected_tags:
        return vulnerabilities

    output: list[Vulnerability] = []
    for vulnerability in vulnerabilities:
        tags = set(vulnerability.platform_tags)
        if not tags:
            output.append(vulnerability)
            continue
        normalized = {tag.casefold() for tag in tags}
        is_generic = bool(tags & GENERIC_PLATFORM_TAGS)
        matches_specific = bool(normalized & selected_tags)
        if matches_specific or (mode == "auto" and include_generic and is_generic):
            output.append(vulnerability)
    return output

