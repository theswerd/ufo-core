"""Persistent Freestyle VMs with proxy-only egress and private SSH port forwarding."""

import asyncio
import errno
import ipaddress
import json
import shlex
import socket
from collections import defaultdict
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import cast
from urllib.parse import quote, urlsplit
from uuid import uuid4

import asyncssh
import httpx
from pydantic import BaseModel, Field

from ufo.sdk.credentials import deploy_env
from ufo.sdk.manifest import Manifest
from ufo.sdk.sandbox import (
    SANDBOX_ENV,
    WORKSPACE_DIR,
    CarrierSpec,
    DialTarget,
    ExecResult,
    SandboxHandle,
    SandboxSpec,
    SandboxUnreachable,
    egress_proxy_env,
    sandbox_runtime_root,
    ufo_fs_file_op,
)

NAME = "freestyle"
API_KEY_ENV = "FREESTYLE_API_KEY"
KNOWN_HOSTS_ENV = "FREESTYLE_SSH_KNOWN_HOSTS"
API_URL = "https://api.freestyle.sh"
SSH_HOST = "beta-ssh.freestyle.sh"
CONTROL_TIMEOUT = 120
IO_TIMEOUT = 120
READ_CHUNK_BYTES = 1024 * 1024
USER = "user"
GUEST_HOME = "/home/user"
GUEST_PATH = "/usr/local/bin:/usr/bin:/bin"
IDLE_TIMEOUT_SECONDS = 1800
MAX_EXEC_REQUEST_BYTES = 48 * 1024

SIGNAL_PROGRAM = """
import os, pathlib, signal, sys

def kill_groups(marker):
    groups = set()
    current = os.getpgrp()
    proc = pathlib.Path('/proc')
    for directory in proc.iterdir() if proc.is_dir() else ():
        if not directory.name.isdigit():
            continue
        try:
            if marker in (directory / 'environ').read_bytes().split(b'\\0'):
                group = os.getpgid(int(directory.name))
                if group != current:
                    groups.add(group)
        except OSError:
            pass
    for group in groups:
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass
"""
EXEC_PROGRAM = (
    SIGNAL_PROGRAM
    + """
import json, subprocess, tempfile, uuid
request = json.loads(sys.argv[1])
exec_id = str(uuid.uuid4())
request['env']['UFO_FREESTYLE_EXEC_ID'] = exec_id
timed_out = None
try:
    process = subprocess.Popen(request['argv'], cwd=request['cwd'], env=request['env'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
except OSError as error:
    outcome = dict(stdout='', stderr=str(error), exit_code=127 if error.errno == 2 else 126)
else:
    try:
        stdout, stderr = process.communicate(timeout=request['timeout'])
    except subprocess.TimeoutExpired:
        timed_out = request['timeout']
        kill_groups(('UFO_FREESTYLE_EXEC_ID=' + exec_id).encode())
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
    outcome = dict(stdout=stdout.decode(errors='replace'), stderr=stderr.decode(errors='replace'),
        exit_code=124 if timed_out is not None else process.returncode, timed_out_after_s=timed_out)
fd, path = tempfile.mkstemp(prefix='ufo-result-', dir=request['result_dir'])
with os.fdopen(fd, 'w') as stream:
    json.dump(outcome, stream)
try:
    print(path, flush=True)
except BrokenPipeError:
    os.unlink(path)
"""
)
STOP_PROGRAM = (
    SIGNAL_PROGRAM
    + """
kill_groups(('UFO_FREESTYLE_TURN_ID=' + sys.argv[1]).encode())
"""
)
PREPARE_SCRIPT = """
set -eu
test "$(id -u user)" = 1000
test "$(id -g user)" = 1000
test -x /usr/local/bin/ufo
test ! -L /home/user/.ufo
install -d -o root -g root -m 0755 /home/user/.ufo
install -d -o user -g user -m 0755 /workspace
install -d -o user -g user -m 0700 "$1"
if [ ! -f /home/user/.ufo/session ]; then
    install -o user -g user -m 0600 /dev/null /home/user/.ufo/session
fi
cat > /usr/local/share/ca-certificates/ufo-egress-ca.crt
update-ca-certificates >/dev/null
sed -i '/ # ufo-egress$/d' /etc/hosts
printf '%s\\n' "$2" >> /etc/hosts
"""


class Vm(BaseModel):
    id: str
    metadata: dict[str, str] = Field(default_factory=dict)


class FirewallRule(BaseModel):
    id: str
    source: dict[str, str | int | bool]
    destination: dict[str, str | int | bool]


class FirewallRules(BaseModel):
    rules: list[FirewallRule]


class Identity(BaseModel):
    id: str


class Token(BaseModel):
    token: str


class CommandResult(BaseModel):
    stdout: str
    stderr: str
    exit_code: int
    timed_out_after_s: int | None = None


@dataclass(frozen=True)
class FreestyleCarrier:
    api_key: str = field(repr=False)
    known_hosts: str
    _tunnels: dict[tuple[str, int], tuple[asyncssh.SSHClientConnection, asyncssh.SSHListener]] = (
        field(default_factory=dict, repr=False)
    )
    _locks: defaultdict[tuple[str, int], asyncio.Lock] = field(
        default_factory=lambda: defaultdict(asyncio.Lock), repr=False
    )

    @classmethod
    def from_env(cls) -> "FreestyleCarrier":
        """Load the host-side API key and the operator's trusted SSH host keys."""
        key = deploy_env(API_KEY_ENV)
        hosts = deploy_env(KNOWN_HOSTS_ENV)
        if not key or not hosts:
            raise RuntimeError(f"set {API_KEY_ENV} and {KNOWN_HOSTS_ENV} for the freestyle carrier")
        return cls(api_key=key, known_hosts=hosts)

    async def create(self, spec: SandboxSpec) -> SandboxHandle:
        """Create or resume the conversation VM; refresh its CA and per-turn environment."""
        env = {**SANDBOX_ENV, **egress_proxy_env(spec.proxy, spec.run_token), **spec.env}
        parsed = urlsplit(spec.proxy.public_url or "")
        host = parsed.hostname
        if host is None:
            raise ValueError("freestyle requires an HTTPS proxy_public_url")
        addresses = await asyncio.get_running_loop().getaddrinfo(
            host, parsed.port or 443, type=socket.SOCK_STREAM
        )
        ips = sorted({str(ipaddress.ip_address(address[4][0])) for address in addresses})
        if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
            raise ValueError("freestyle proxy_public_url must resolve to public IP addresses")
        slug = f"ufo-{spec.conversation_id}"
        vm = await self._find(spec.resume_id or slug)
        if vm is None and spec.resume_id:
            raise SandboxUnreachable(f"Freestyle VM {spec.resume_id} no longer exists")
        if vm is None:
            if not spec.image_ref.startswith("sh-"):
                raise ValueError(
                    "freestyle image_ref must be a prepared, immutable sh- snapshot id"
                )
            rules = [
                {
                    "action": "allow",
                    "source": {},
                    "destination": {
                        "cidr": f"{ip}/{ipaddress.ip_address(ip).max_prefixlen}",
                        "port": parsed.port or 443,
                        "protocol": "tcp",
                    },
                }
                for ip in ips
            ]
            try:
                response = await self._request(
                    "POST",
                    "/v5/vms",
                    {
                        "snapshotId": spec.image_ref,
                        "slug": slug,
                        "metadata": {"ufo_conversation": str(spec.conversation_id)},
                        "idleTimeoutSeconds": IDLE_TIMEOUT_SECONDS,
                        "firewall": {"rules": rules},
                    },
                )
                vm = Vm.model_validate_json(response.content)
            except httpx.HTTPStatusError as error:
                if error.response.status_code != 409:
                    raise
                vm = await self._find(slug)
                if vm is None:
                    raise
        self._check_owner(vm, spec)
        await self._sync_firewall(vm.id, ips, parsed.port or 443)
        hosts = "\n".join(f"{ip} {host} # ufo-egress" for ip in ips)
        async with self._ssh(vm.id, "root") as connection:
            await connection.run(
                shlex.join(
                    (
                        "sh",
                        "-c",
                        PREPARE_SCRIPT,
                        "sh",
                        sandbox_runtime_root(spec.conversation_id),
                        hosts,
                    )
                ),
                input=spec.proxy.ca_cert,
                check=True,
                timeout=CONTROL_TIMEOUT,
            )
        return SandboxHandle(
            conversation_id=spec.conversation_id,
            container_id=vm.id,
            run_token=spec.run_token,
            egress_env=env,
            turn_id=spec.turn_id,
            runtime_root=sandbox_runtime_root(spec.conversation_id),
        )

    async def attach(self, spec: SandboxSpec) -> SandboxHandle | None:
        """Find an existing VM without provisioning or giving file reads egress credentials."""
        vm = await self._find(spec.resume_id or f"ufo-{spec.conversation_id}")
        if vm is None:
            return None
        self._check_owner(vm, spec)
        return SandboxHandle(
            conversation_id=spec.conversation_id,
            container_id=vm.id,
            runtime_root=sandbox_runtime_root(spec.conversation_id),
            turn_id=spec.turn_id,
        )

    def _check_owner(self, vm: Vm, spec: SandboxSpec) -> None:
        if vm.metadata.get("ufo_conversation") != str(spec.conversation_id):
            raise SandboxUnreachable("Freestyle VM belongs to another conversation")

    async def _sync_firewall(self, vm_id: str, ips: list[str], port: int) -> None:
        response = await self._request("GET", f"/v5/firewall/rules?vmId={quote(vm_id, safe='')}")
        applied = FirewallRules.model_validate_json(response.content)
        desired = [
            {
                "cidr": f"{ip}/{ipaddress.ip_address(ip).max_prefixlen}",
                "port": port,
                "protocol": "tcp",
            }
            for ip in ips
        ]
        for rule in applied.rules:
            if rule.source != {"vmId": vm_id} or set(rule.destination) != {
                "cidr",
                "port",
                "protocol",
            }:
                raise RuntimeError("Freestyle sandbox has firewall rules outside its proxy policy")
        for rule in applied.rules:
            if rule.destination not in desired:
                await self._request("DELETE", f"/v5/firewall/rules/{quote(rule.id, safe='')}")
        for destination in desired:
            if not any(rule.destination == destination for rule in applied.rules):
                await self._request(
                    "POST",
                    "/v5/firewall/rules",
                    {
                        "action": "allow",
                        "source": {"vmId": vm_id},
                        "destination": destination,
                    },
                )

    async def stop_commands(self, handle: SandboxHandle) -> None:
        """Stop this turn's process groups, including detached UFO command supervisors."""
        if handle.turn_id is None:
            return
        result = await self._exec(
            handle,
            ("python3", "-I", "-c", STOP_PROGRAM, str(handle.turn_id)),
            CONTROL_TIMEOUT,
            USER,
            {"UFO_FREESTYLE_TURN_ID": ""},
        )
        if result.exit_code != 0:
            raise RuntimeError(result.stderr or "Freestyle command cancellation failed")

    async def exec(
        self,
        handle: SandboxHandle,
        argv: tuple[str, ...],
        timeout_s: int,
        model_command: str | None = None,
    ) -> ExecResult:
        return await self._exec(handle, argv, timeout_s, USER, handle.egress_env)

    async def exec_skill(
        self,
        handle: SandboxHandle,
        argv: tuple[str, ...],
        timeout_s: int,
    ) -> ExecResult:
        """Execute the runtime's trusted skill installation as root."""
        return await self._exec(handle, argv, timeout_s, "root", {})

    async def _exec(
        self,
        handle: SandboxHandle,
        argv: tuple[str, ...],
        timeout_s: int,
        user: str,
        env: Mapping[str, str],
    ) -> ExecResult:
        request = json.dumps(
            {
                "argv": argv,
                "cwd": WORKSPACE_DIR,
                "result_dir": "/var/tmp",
                "timeout": timeout_s,
                "env": {
                    "PATH": GUEST_PATH,
                    "HOME": GUEST_HOME,
                    **SANDBOX_ENV,
                    "UFO_FREESTYLE_TURN_ID": str(handle.turn_id or ""),
                    **env,
                },
            }
        )
        if len(request.encode()) > MAX_EXEC_REQUEST_BYTES:
            raise ValueError("Freestyle exec argv and environment exceed 48 KiB; use file transfer")
        async with self._ssh(handle.container_id, user) as connection:
            result = await connection.run(
                shlex.join(("python3", "-I", "-c", EXEC_PROGRAM, request)),
                check=True,
                timeout=timeout_s + CONTROL_TIMEOUT,
            )
            result_path = str(result.stdout or "").strip()
            if (
                not result_path.startswith("/var/tmp/ufo-result-")
                or len(PurePosixPath(result_path).parts) != 4
            ):
                raise RuntimeError("Freestyle command returned no result file")
            async with connection.start_sftp_client() as sftp:
                try:
                    async with asyncio.timeout(IO_TIMEOUT):
                        async with sftp.open(result_path, "rb", encoding=None) as source:
                            content = cast(bytes, await source.read())
                    outcome = CommandResult.model_validate_json(content)
                finally:
                    await sftp.remove(result_path)
        return ExecResult(**outcome.model_dump())

    async def write(self, handle: SandboxHandle, path: str, content: bytes) -> None:
        """Atomically upload acknowledged SFTP blocks as the sandbox user."""
        parent = str(PurePosixPath(path).parent)
        staged = f"{parent}/.ufo-{uuid4()}"
        async with self._ssh(handle.container_id, USER) as connection:
            async with connection.start_sftp_client() as sftp:
                async with asyncio.timeout(IO_TIMEOUT):
                    await sftp.makedirs(parent, exist_ok=True)
                    try:
                        mode = (await sftp.stat(path)).permissions
                    except asyncssh.SFTPNoSuchFile:
                        mode = None
                    try:
                        async with sftp.open(staged, "xb") as target:
                            for offset in range(0, len(content), READ_CHUNK_BYTES):
                                await target.write(content[offset : offset + READ_CHUNK_BYTES])
                        await sftp.chmod(staged, mode & 0o777 if mode is not None else 0o644)
                        await sftp.posix_rename(staged, path)
                    finally:
                        with suppress(asyncssh.SFTPNoSuchFile):
                            await sftp.remove(staged)

    async def read(self, handle: SandboxHandle, path: str) -> AsyncIterator[bytes]:
        """Read acknowledged SFTP blocks without buffering the file on the host."""
        async with self._ssh(handle.container_id, USER) as connection:
            async with connection.start_sftp_client() as sftp:
                try:
                    async with asyncio.timeout(IO_TIMEOUT):
                        async with sftp.open(path, "rb", encoding=None) as source:
                            while chunk := cast(bytes, await source.read(READ_CHUNK_BYTES)):
                                yield chunk
                except asyncssh.SFTPNoSuchFile as error:
                    raise FileNotFoundError(
                        errno.ENOENT, "Freestyle file not found", path
                    ) from error
                except asyncssh.SFTPPermissionDenied as error:
                    raise PermissionError(
                        errno.EACCES, "Freestyle file permission denied", path
                    ) from error

    async def file_op(
        self,
        handle: SandboxHandle,
        op: str,
        params: dict[str, object],
    ) -> dict[str, object]:
        return await ufo_fs_file_op(self, handle, op, params)

    async def dial(self, handle: SandboxHandle, port: int) -> DialTarget:
        """Forward a loopback-only host port through authenticated SSH; publish no guest port."""
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        key = (handle.container_id, port)
        async with self._locks[key]:
            held = self._tunnels.get(key)
            if held is not None and held[0].is_closed():
                held[1].close()
                del self._tunnels[key]
                held = None
            if held is None:
                connection = None
                try:
                    connection = await self._connect(handle.container_id, USER)
                    listener = await connection.forward_local_port(
                        "127.0.0.1", 0, "127.0.0.1", port
                    )
                    held = (connection, listener)
                    self._tunnels[key] = held
                except (asyncssh.Error, OSError, httpx.HTTPError) as error:
                    if connection is not None:
                        connection.close()
                        await connection.wait_closed()
                    raise SandboxUnreachable("Freestyle SSH port forwarding failed") from error
        return DialTarget(host=f"127.0.0.1:{held[1].get_port()}", tls=False)

    async def aclose(self) -> None:
        """Release this carrier's local forwarding listeners and SSH connections."""
        for connection, listener in self._tunnels.values():
            listener.close()
            connection.close()
            await connection.wait_closed()
        self._tunnels.clear()

    @asynccontextmanager
    async def _ssh(self, vm_id: str, user: str) -> AsyncIterator[asyncssh.SSHClientConnection]:
        connection = await self._connect(vm_id, user)
        try:
            yield connection
        finally:
            connection.close()
            await connection.wait_closed()

    async def _connect(self, vm_id: str, user: str) -> asyncssh.SSHClientConnection:
        response = await self._request("POST", "/v5/identities", {})
        identity = Identity.model_validate_json(response.content)
        base = f"/v5/identities/{quote(identity.id, safe='')}"
        connection = None
        try:
            await self._request(
                "POST",
                f"{base}/permissions/vm",
                {
                    "vmId": vm_id,
                    "allowedLinuxUsers": [user],
                },
            )
            response = await self._request("POST", f"{base}/tokens", {})
            token = Token.model_validate_json(response.content)
            connection = await asyncssh.connect(
                SSH_HOST,
                username=f"{vm_id}+{user}",
                password=token.token,
                known_hosts=self.known_hosts,
                client_keys=[],
                agent_path=None,
                connect_timeout=CONTROL_TIMEOUT,
            )
        finally:
            try:
                await self._request("DELETE", base)
            except BaseException:
                if connection is not None:
                    connection.close()
                    await connection.wait_closed()
                raise
        return connection

    async def _find(self, vm_id: str) -> Vm | None:
        response = await self._request("GET", f"/v5/vms/{quote(vm_id, safe='')}", missing=True)
        return None if response.status_code == 404 else Vm.model_validate_json(response.content)

    async def _request(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
        *,
        missing: bool = False,
    ) -> httpx.Response:
        async with httpx.AsyncClient(
            base_url=API_URL,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=CONTROL_TIMEOUT,
        ) as client:
            response = await client.request(method, path, json=body)
        if not (missing and response.status_code == 404):
            response.raise_for_status()
        return response


def manifest() -> Manifest:
    return Manifest(
        name=NAME,
        version="0.1.0",
        deploy_keys=(API_KEY_ENV,),
        carriers=(CarrierSpec(name=NAME, factory=FreestyleCarrier.from_env, off_cluster=True),),
    )
