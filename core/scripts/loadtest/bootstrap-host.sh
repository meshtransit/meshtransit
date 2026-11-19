#!/usr/bin/env bash
# Prepares a disposable load-test host: Docker, Go, and kernel limits for
# ~100k loopback TCP sessions. Run once as root.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq docker.io openssl rsync >/dev/null
systemctl enable --now docker >/dev/null
GO_VERSION=1.26.11
# SHA-256 of go1.26.11.linux-amd64.tar.gz as published on go.dev/dl.
GO_SHA256=9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec
if [[ "$(/usr/local/go/bin/go version 2>/dev/null || true)" != "go version go${GO_VERSION} linux/amd64" ]]; then
	download="$(mktemp -d)"
	trap 'rm -rf "${download:?}"' EXIT
	curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o "${download}/go.tgz"
	echo "${GO_SHA256}  ${download}/go.tgz" | sha256sum --check --quiet -
	rm -rf /usr/local/go && tar -C /usr/local -xzf "${download}/go.tgz"
fi
cat >/etc/sysctl.d/90-meshtransit-loadtest.conf <<'SYSCTL'
fs.file-max = 4194304
fs.nr_open = 4194304
net.ipv4.ip_local_port_range = 1024 65535
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
SYSCTL
sysctl --system >/dev/null
echo "host ready: $(/usr/local/go/bin/go version), $(docker --version)"
