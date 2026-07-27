"""Shared SSH connection helper used by every SSH-backed tool."""

from contextlib import contextmanager
from pathlib import Path

import paramiko

_SSH_CONNECT_TIMEOUT = 10
_SSH_PORT = 22


@contextmanager
def ssh_client(server_ip: str, os_user: str, ssh_key: str):
    key_path = Path(ssh_key).expanduser()
    if not key_path.is_file():
        raise FileNotFoundError(f"SSH key not found: {key_path}")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    # Strict host key checking disabled: unknown hosts are auto-accepted rather
    # than requiring a known_hosts entry (equivalent to StrictHostKeyChecking=no).
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
        yield client
    finally:
        client.close()
