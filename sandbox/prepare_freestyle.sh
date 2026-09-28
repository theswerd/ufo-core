#!/bin/sh
set -eu

client=${1:?usage: prepare_freestyle.sh /path/to/linux/ufo}
test -x "$client"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl git jq python3 python3-venv ripgrep openssh-sftp-server
if id ubuntu >/dev/null 2>&1; then
    usermod -l user -d /home/user -m ubuntu
    groupmod -n user ubuntu
fi
id user >/dev/null 2>&1 || useradd -m -u 1000 -s /bin/bash user
test "$(id -u user)" = 1000
test "$(id -g user)" = 1000
usermod -G '' user
SUDO_FORCE_REMOVE=yes apt-get remove -y sudo
rm -rf /etc/sudoers /etc/sudoers.d
install -m 0755 "$client" /usr/local/bin/ufo
chown root:root /home/user
chmod 0755 /home/user
install -d -o root -g root -m 0755 /home/user/.ufo /home/user/.ufo/runs
install -d -o root -g root -m 1777 /home/user/.ufo/skills
install -o user -g user -m 0600 /dev/null /home/user/.ufo/session
install -d -o user -g user -m 0700 /home/user/.cache
install -d -o user -g user -m 0755 /workspace
