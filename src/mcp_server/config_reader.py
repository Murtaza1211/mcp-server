"""Read and sanitize Liberty-style server config over SSH (server.xml + related property files)."""

import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import paramiko

from .sanitize import sanitize

# Files every server config is expected to (optionally) have, beyond server.xml itself.
_FIXED_FILES = ("jvm.options", "server.env", "bootstrap.properties")

# <include location="..."/> references (may point at .xml or .properties files).
_INCLUDE_RE = re.compile(r'<include\b[^>]*\blocation\s*=\s*"([^"]+)"', re.IGNORECASE)

# Any quoted path ending in .properties, e.g. variable/property file references.
_PROPERTIES_REF_RE = re.compile(r'"([^"]+\.properties)"', re.IGNORECASE)

_VARIABLE_PLACEHOLDER_RE = re.compile(r"\$\{[^}]+\}")

_SSH_CONNECT_TIMEOUT = 10
_SSH_PORT = 22


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


@contextmanager
def _sftp_session(server_ip: str, os_user: str, ssh_key: str):
    key_path = Path(ssh_key).expanduser()
    if not key_path.is_file():
        raise FileNotFoundError(f"SSH key not found: {key_path}")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    # Refuse unknown hosts rather than silently trusting them (no AutoAddPolicy) -
    # the target server must already be in the connecting user's known_hosts.
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            hostname=server_ip,
            port=_SSH_PORT,
            username=os_user,
            key_filename=str(key_path),
            timeout=_SSH_CONNECT_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        sftp = client.open_sftp()
        try:
            yield sftp
        finally:
            sftp.close()
    finally:
        client.close()


def _is_dir(sftp: paramiko.SFTPClient, path: PurePosixPath) -> bool:
    try:
        attr = sftp.stat(str(path))
    except FileNotFoundError:
        return False
    return attr.st_mode is not None and stat.S_ISDIR(attr.st_mode)


def _resolve_within(sftp: paramiko.SFTPClient, app_dir_real: str, app_dir: PurePosixPath, ref: str) -> PurePosixPath | None:
    """Resolve a reference relative to app_dir, refusing to leave it. None if unresolvable."""
    if _VARIABLE_PLACEHOLDER_RE.search(ref):
        # Can't resolve Liberty variable substitutions (e.g. ${server.config.dir}) without
        # a full variable-resolution pass, so skip rather than guess.
        return None
    candidate = app_dir / ref
    try:
        real = sftp.normalize(str(candidate))
    except (OSError, FileNotFoundError):
        # File doesn't exist (yet) remotely - fall back to lexical containment check.
        real = str(candidate)
    if not (real == app_dir_real or real.startswith(app_dir_real.rstrip("/") + "/")):
        return None
    return candidate


def _read_file(sftp: paramiko.SFTPClient, path: PurePosixPath, display_name: str) -> FileResult:
    try:
        attr = sftp.stat(str(path))
    except FileNotFoundError:
        return FileResult(path=display_name, found=False)
    if attr.st_mode is not None and stat.S_ISDIR(attr.st_mode):
        return FileResult(path=display_name, found=False, error="is a directory")
    try:
        with sftp.open(str(path), "r") as f:
            raw = f.read().decode("utf-8", errors="replace")
    except OSError as e:
        return FileResult(path=display_name, found=True, error=str(e))
    return FileResult(path=display_name, found=True, content=sanitize(raw))


def read_config(server_ip: str, os_user: str, ssh_key: str, deployment_directory: str, application: str) -> dict:
    """SSH to server_ip and read server.xml plus its related config files, secrets redacted."""
    app_dir = PurePosixPath(deployment_directory) / application

    try:
        with _sftp_session(server_ip, os_user, ssh_key) as sftp:
            if not _is_dir(sftp, app_dir):
                return {
                    "server": server_ip,
                    "application_directory": str(app_dir),
                    "error": f"Directory not found on {server_ip}: {app_dir}",
                    "files": [],
                }

            app_dir_real = sftp.normalize(str(app_dir))

            server_xml_result = _read_file(sftp, app_dir / "server.xml", "server.xml")
            results: list[FileResult] = [server_xml_result]

            referenced: set[str] = set()
            if server_xml_result.content:
                referenced = _find_referenced_files(server_xml_result.content)

            files_to_read = set(_FIXED_FILES)
            for ref in sorted(referenced):
                resolved = _resolve_within(sftp, app_dir_real, app_dir, ref)
                if resolved is None:
                    results.append(
                        FileResult(path=ref, found=False, error="unresolved or outside application directory")
                    )
                    continue
                files_to_read.add(str(resolved.relative_to(app_dir)))

            for rel in sorted(files_to_read):
                results.append(_read_file(sftp, app_dir / rel, rel))
    except paramiko.AuthenticationException as e:
        return {"server": server_ip, "application_directory": str(app_dir), "error": f"SSH authentication failed: {e}", "files": []}
    except (paramiko.SSHException, OSError, FileNotFoundError) as e:
        return {"server": server_ip, "application_directory": str(app_dir), "error": f"SSH connection failed: {e}", "files": []}

    return {
        "server": server_ip,
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
