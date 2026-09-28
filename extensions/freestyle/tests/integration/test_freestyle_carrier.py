import asyncio
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ufo_ext_freestyle import FreestyleCarrier

from ufo.sdk.sandbox import ProxyEndpoint, SandboxSession, SandboxSpec, SandboxUnreachable

SNAPSHOT = os.environ.get("UFO_FREESTYLE_TEST_SNAPSHOT")
pytestmark = pytest.mark.skipif(not SNAPSHOT, reason="set UFO_FREESTYLE_TEST_SNAPSHOT to opt in")


async def test_live_freestyle_carrier() -> None:
    carrier = FreestyleCarrier.from_env()
    conversation = uuid4()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "UFO test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    spec = SandboxSpec(
        conversation_id=conversation,
        image_ref=SNAPSHOT or "",
        workspace_host_path="/unused",
        proxy=ProxyEndpoint(port=443, ca_cert=cert, public_url="https://example.com"),
        run_token="turn-one",
        turn_id=uuid4(),
        env={"TEST_VALUE": "one"},
    )
    second = FreestyleCarrier(api_key=carrier.api_key, known_hosts=carrier.known_hosts)
    try:
        assert await carrier.attach(spec) is None
        handle = await carrier.create(spec)
        await carrier._request("PATCH", f"/v5/vms/{handle.container_id}", {"ttlSeconds": 3600})
        sandbox = SandboxSession(carrier=carrier, handle=handle)
        result = await sandbox.sh('printf "%s:%s:%s" "$(id -u)" "$TEST_VALUE" "$HTTPS_PROXY"')
        assert result.stdout.startswith("1000:one:https://turn-one:")
        assert carrier.api_key not in result.stdout
        large = await sandbox.python("print('x' * 2097408, end='')")
        assert len(large.stdout) == 2097408
        content = bytes(range(256)) * 8193
        path = "/workspace/nested/quotes ' and spaces.bin"
        await sandbox.write_file(path, content)
        chunks = [chunk async for chunk in sandbox.read_file(path)]
        assert len(b"".join(chunks)) == len(content)
        assert b"".join(chunks) == content
        assert max(map(len, chunks)) <= 1024 * 1024
        with pytest.raises(FileNotFoundError):
            _ = [chunk async for chunk in sandbox.read_file("/workspace/missing")]
        with pytest.raises(PermissionError):
            _ = [chunk async for chunk in carrier.read(handle, "/etc/shadow")]
        await sandbox.write_file("/workspace/hello.txt", b"hello freestyle\n")
        result = await sandbox.run_ufo_fs("read", {"path": "/workspace/hello.txt"})
        assert "hello freestyle" in str(result)
        loaded = await sandbox.load_skills({"system": {}, "user": {}})
        assert loaded == {}
        result = await sandbox.sh("sleep 30", timeout_s=1)
        assert result.exit_code == 124 and result.timed_out_after_s == 1
        result = await sandbox.sh("exit 124")
        assert result.exit_code == 124 and result.timed_out_after_s is None
        result = await carrier.exec(handle, ("no-such-ufo-command",), 10)
        assert result.exit_code == 127
        result = await sandbox.python(
            "import socket; socket.create_connection(('1.1.1.1', 443), timeout=2)",
        )
        assert result.exit_code != 0
        served = await sandbox.python(
            "import subprocess; subprocess.Popen(['python3', '-m', 'http.server', '8765', "
            "'--bind', '127.0.0.1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"
        )
        assert served.exit_code == 0
        target = await carrier.dial(handle, 8765)
        async with httpx.AsyncClient() as client:
            response = await client.get(f"http://{target.host}/hello.txt")
            assert response.text == "hello freestyle\n"
        assert await carrier.dial(handle, 8765) == target
        await carrier.aclose()
        await carrier._request("POST", f"/v5/vms/{handle.container_id}/pause", {})
        attached = await second.attach(replace(spec, resume_id=handle.container_id))
        assert attached is not None and not attached.egress_env
        assert b"".join([chunk async for chunk in second.read(attached, path)]) == content
        resumed = await second.create(
            replace(
                spec, resume_id=handle.container_id, run_token="turn-two", env={"TEST_VALUE": "two"}
            )
        )
        assert resumed.container_id == handle.container_id
        result = await second.exec(resumed, ("sh", "-c", 'echo "$TEST_VALUE:$HTTPS_PROXY"'), 10)
        assert result.stdout.startswith("two:https://turn-two:")
        with pytest.raises(SandboxUnreachable):
            await second.attach(
                replace(spec, conversation_id=uuid4(), resume_id=handle.container_id)
            )
        sibling = replace(resumed, turn_id=uuid4())
        running = asyncio.create_task(second.exec(resumed, ("sleep", "30"), 40))
        other = asyncio.create_task(second.exec(sibling, ("sleep", "5"), 40))
        await asyncio.sleep(3)
        await second.stop_commands(resumed)
        assert (await asyncio.wait_for(running, 15)).exit_code != 0
        assert (await other).exit_code == 0
        await second._request("DELETE", f"/v5/vms/{handle.container_id}")
        assert await second.attach(replace(spec, resume_id=handle.container_id)) is None
        with pytest.raises(SandboxUnreachable):
            await second.create(replace(spec, resume_id=handle.container_id))
    finally:
        await carrier.aclose()
        await second.aclose()
        vm = await carrier._find(f"ufo-{conversation}")
        if vm is not None:
            await carrier._request("DELETE", f"/v5/vms/{vm.id}")
