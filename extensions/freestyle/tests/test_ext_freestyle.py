import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from ufo_ext_freestyle import (
    EXEC_PROGRAM,
    FreestyleCarrier,
    Vm,
    manifest,
)

from ufo.config import BlobConfig, Config, DatabaseConfig, SandboxConfig
from ufo.harness.sandbox.select import select_carriers
from ufo.sdk.sandbox import ProxyEndpoint, SandboxSpec, SandboxUnreachable


def test_carrier_selection_and_host_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FREESTYLE_API_KEY", "private-key")
    monkeypatch.setenv("FREESTYLE_SSH_KNOWN_HOSTS", "/etc/ufo/ssh_known_hosts")
    config = Config(
        database=DatabaseConfig(url="sqlite+aiosqlite:///carrier.db"),
        blob=BlobConfig(backend="filesystem", root=Path("blobs")),
        sandbox=SandboxConfig(
            backend="freestyle",
            proxy_public_url="https://proxy.example.com",
        ),
    )
    selected = select_carriers(config, (manifest(),))
    assert isinstance(selected.carrier, FreestyleCarrier)
    assert selected.spec.off_cluster
    assert "private-key" not in repr(selected.carrier)
    assert manifest().deploy_keys == ("FREESTYLE_API_KEY",)


@pytest.mark.parametrize("url", [None, "http://proxy.example.com"])
def test_remote_carrier_requires_tls_proxy(url: str | None) -> None:
    with pytest.raises(RuntimeError, match="HTTPS"):
        select_carriers(
            Config(
                database=DatabaseConfig(url="sqlite+aiosqlite:///carrier.db"),
                blob=BlobConfig(backend="filesystem", root=Path("blobs")),
                sandbox=SandboxConfig(
                    backend="freestyle",
                    proxy_public_url=url,
                ),
            ),
            (manifest(),),
        )


def test_missing_credentials_fail_at_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "FREESTYLE_API_KEY",
        "UFO_FREESTYLE_API_KEY",
        "FREESTYLE_SSH_KNOWN_HOSTS",
        "UFO_FREESTYLE_SSH_KNOWN_HOSTS",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="FREESTYLE_API_KEY"):
        FreestyleCarrier.from_env()


def test_resume_requires_conversation_ownership() -> None:
    spec = SandboxSpec(
        conversation_id=uuid4(),
        image_ref="sh-example",
        workspace_host_path="",
        proxy=ProxyEndpoint(port=443, ca_cert=""),
        run_token="",
    )
    vm = Vm(id="vm-example", metadata={"ufo_conversation": str(spec.conversation_id)})
    carrier = FreestyleCarrier(api_key="key", known_hosts="hosts")
    carrier._check_owner(vm, spec)
    with pytest.raises(SandboxUnreachable, match="another conversation"):
        carrier._check_owner(vm, replace(spec, conversation_id=uuid4()))


@pytest.mark.parametrize("exit_code", [0, 7, 124])
def test_guest_exec_preserves_arguments_environment_and_exit_status(
    tmp_path: Path,
    exit_code: int,
) -> None:
    literal = "spaces ' quotes $HOME $(touch unexpected)\nnewline"
    request = {
        "argv": [
            sys.executable,
            "-c",
            "import os,sys; print(sys.argv[1]); "
            "print(os.environ['VALUE'], file=sys.stderr); sys.exit(int(sys.argv[2]))",
            literal,
            str(exit_code),
        ],
        "env": {"VALUE": literal},
        "cwd": str(tmp_path),
        "result_dir": str(tmp_path),
        "timeout": 10,
    }
    result = subprocess.run(
        [sys.executable, "-I", "-c", EXEC_PROGRAM, json.dumps(request)],
        capture_output=True,
        check=True,
        timeout=15,
    )
    result_path = Path(result.stdout.decode().strip())
    outcome = json.loads(result_path.read_bytes())
    result_path.unlink()
    assert outcome == {
        "stdout": literal + "\n",
        "stderr": literal + "\n",
        "exit_code": exit_code,
        "timed_out_after_s": None,
    }
    assert not (tmp_path / "unexpected").exists()


def test_guest_exec_deadline_kills_descendants(tmp_path: Path) -> None:
    request = {
        "argv": ["sh", "-c", "(sleep 2; touch escaped) & wait"],
        "env": {"PATH": os.defpath},
        "cwd": str(tmp_path),
        "result_dir": str(tmp_path),
        "timeout": 1,
    }
    result = subprocess.run(
        [sys.executable, "-I", "-c", EXEC_PROGRAM, json.dumps(request)],
        capture_output=True,
        check=True,
        timeout=5,
    )
    result_path = Path(result.stdout.decode().strip())
    outcome = json.loads(result_path.read_bytes())
    result_path.unlink()
    assert outcome["exit_code"] == 124
    assert outcome["timed_out_after_s"] == 1
    subprocess.run(["sleep", "2"], check=True)
    assert not (tmp_path / "escaped").exists()
