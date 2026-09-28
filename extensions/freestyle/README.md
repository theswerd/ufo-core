# Freestyle sandbox carrier

Freestyle runs one persistent Linux VM per conversation. Files survive pauses and UFO restarts;
VMs idle for 30 minutes pause with memory intact. Freestyle plan retention limits still apply.
The API key stays on the UFO host. Commands and file transfers run as `user` (uid/gid 1000), while
CA installation and trusted skill setup run as root. Preview ports use authenticated SSH forwards
bound to the UFO host's loopback interface.

## Prepare a snapshot

Start with an Ubuntu VM and a Linux `ufo` client built from this checkout. On Linux:

```bash
cargo build --locked --release --manifest-path client/Cargo.toml
npx -y freestyle@latest vm create --snapshot-id freestyle/ubuntu --slug ufo-image --no-ssh
npx -y freestyle@latest vm fs write ufo-image /root/ufo ./client/target/release/ufo
npx -y freestyle@latest vm fs write ufo-image /root/prepare.sh ./sandbox/prepare_freestyle.sh
npx -y freestyle@latest vm exec ufo-image --linux-user root -- chmod +x /root/ufo
npx -y freestyle@latest vm exec ufo-image --linux-user root -- sh /root/prepare.sh /root/ufo
npx -y freestyle@latest snapshot create ufo-image --output json
npx -y freestyle@latest vm delete ufo-image
```

The preparation script installs the file/shell toolchain, removes sudo, and prepares UFO's runtime
directories. Install any additional tools your extensions need before taking the snapshot, such as
Node.js and Chrome for `sandbox_chrome`. Choose the VM's resources before snapshotting; the carrier
inherits that shape. Use the returned immutable `snapshotId` (`sh-…`) as `image_ref` below. Keep the
snapshot; it is the source of new conversations. The carrier does not build images during a turn.

## Configure UFO

Set these host-side environment variables (the prefixed API key also works in `.env`):

```bash
export UFO_FREESTYLE_API_KEY="your-api-key"
export FREESTYLE_SSH_KNOWN_HOSTS="/etc/ufo/ssh_known_hosts"
```

The known-hosts file must contain a verified SSH host key for `beta-ssh.freestyle.sh`. Obtain and
verify it through your normal SSH host-key provisioning process. Host verification is mandatory.
See [Freestyle SSH access](https://www.freestyle.sh/docs/vms/ssh).

In `ufo.toml`:

```toml
[sandbox]
backend = "freestyle"
image_ref = "sh-your-prepared-snapshot-id"
proxy_public_url = "https://egress.example.com"
```

`proxy_public_url` must expose **UFO's egress proxy**, with a valid public TLS certificate and a
public address dedicated to that proxy. It is not the chat server URL. A fresh VM's firewall allows
only TCP to this proxy's resolved IPs and port; no general Internet or inbound rule is installed.
The hostname is pinned in `/etc/hosts`, so guest DNS needs no outbound allowance. Avoid sharing the
proxy's IP and port with unrelated services. Do not add broader account or VM firewall rules: they
would bypass the intended egress boundary.

The `assistant` pack includes the carrier. Custom packs must include `freestyle`; locked deploys
must pin it with their other extensions. Start a conversation with `ufo --remote` to use it.
Interactive PTY attachment is not exposed by this carrier.

Deleting a conversation VM deletes its workspace. A stored handle whose VM was deleted raises an
error rather than silently provisioning an empty workspace. Use the Freestyle dashboard or CLI for
VM deletion, snapshots, resource resizing, and branching. A failed initial preparation leaves the
VM under its `ufo-<conversation-id>` slug for inspection and a later retry.

## Validate

```bash
make test-one FILE=extensions/freestyle/tests/test_ext_freestyle.py
UFO_FREESTYLE_TEST_SNAPSHOT=sh-your-prepared-snapshot-id \
  uv run pytest -q extensions/freestyle/tests/integration/test_freestyle_carrier.py
```

The opt-in live test provisions and deletes a VM, exercises command deadlines, files, `ufo fs`,
skill loading, private port forwarding, blocked direct Internet access, pause/resume, per-turn
credentials, cancellation, and missing-handle behavior. It needs the same API key and known-hosts
file as the carrier. It uses a test CA and checks proxy configuration, not a live model request.
