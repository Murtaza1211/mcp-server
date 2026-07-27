"""Read and sanitize Liberty-style server config (server.xml + related property files)."""

import re
from dataclasses import dataclass
from pathlib import Path

from .sanitize import sanitize

# Files every server config is expected to (optionally) have, beyond server.xml itself.
_FIXED_FILES = ("jvm.options", "server.env", "bootstrap.properties")

# <include location="..."/> references (may point at .xml or .properties files).
_INCLUDE_RE = re.compile(r'<include\b[^>]*\blocation\s*=\s*"([^"]+)"', re.IGNORECASE)

# Any quoted path ending in .properties, e.g. variable/property file references.
_PROPERTIES_REF_RE = re.compile(r'"([^"]+\.properties)"', re.IGNORECASE)

_VARIABLE_PLACEHOLDER_RE = re.compile(r"\$\{[^}]+\}")


@dataclass
class FileResult:
    path: str
    found: bool
    content: str | None = None
    error: str | None = None


def _find_referenced_files(server_xml_text: str) -> set[str]:
    refs = set(m.group(1) for m in _INCLUDE_RE.finditer(server_xml_text))
    refs.update(m.group(1) for m in _PROPERTIES_REF_RE.finditer(server_xml_text))
    return refs


def _resolve_within(app_dir: Path, ref: str) -> Path | None:
    """Resolve a reference relative to app_dir, refusing to leave it. None if unresolvable."""
    if _VARIABLE_PLACEHOLDER_RE.search(ref):
        # Can't resolve Liberty variable substitutions (e.g. ${server.config.dir}) without
        # a full variable-resolution pass, so skip rather than guess.
        return None
    candidate = (app_dir / ref).resolve()
    try:
        candidate.relative_to(app_dir.resolve())
    except ValueError:
        return None
    return candidate


def _read_file(path: Path, display_name: str) -> FileResult:
    if not path.is_file():
        return FileResult(path=display_name, found=False)
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return FileResult(path=display_name, found=True, error=str(e))
    return FileResult(path=display_name, found=True, content=sanitize(raw))


def read_config(deployment_directory: str, application: str) -> dict:
    """Read server.xml and its related config files for an app, with secrets redacted."""
    app_dir = Path(deployment_directory).expanduser() / application

    if not app_dir.is_dir():
        return {
            "application_directory": str(app_dir),
            "error": f"Directory not found: {app_dir}",
            "files": [],
        }

    app_dir = app_dir.resolve()

    server_xml_path = app_dir / "server.xml"
    results: list[FileResult] = []

    server_xml_result = _read_file(server_xml_path, "server.xml")
    results.append(server_xml_result)

    referenced: set[str] = set()
    if server_xml_result.content:
        referenced = _find_referenced_files(server_xml_result.content)

    files_to_read = set(_FIXED_FILES)
    for ref in sorted(referenced):
        resolved = _resolve_within(app_dir, ref)
        if resolved is None:
            results.append(FileResult(path=ref, found=False, error="unresolved or outside application directory"))
            continue
        files_to_read.add(resolved.relative_to(app_dir).as_posix())

    for rel in sorted(files_to_read):
        results.append(_read_file(app_dir / rel, rel))

    return {
        "application_directory": str(app_dir),
        "files": [
            {
                "path": r.path,
                "found": r.found,
                **({"content": r.content} if r.content is not None else {}),
                **({"error": r.error} if r.error else {}),
            }
            for r in results
        ],
    }
