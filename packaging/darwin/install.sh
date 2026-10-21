#!/bin/bash
# Installs the MeshTransit client on macOS from an extracted release tarball.
# Run as root from the tarball directory: sudo ./install.sh
#
#   /usr/local/libexec/meshtransit/{meshd,meshnetd,meshcred}  daemons
#   /usr/local/bin/meshctl                                     command line
#   /Library/LaunchDaemons/net.meshtransit.{meshnetd,meshnetd-captive,meshd}.plist
#   /Library/Application Support/MeshTransit/                  key and state
#   /var/log/meshtransit/                                      logs
#
# meshd runs as the hidden user _meshd; members of the meshtransit group (the
# installing user is added) can use meshctl without sudo after logging in
# again. Reinstalling keeps the identity key and state.
set -euo pipefail

readonly libexec=/usr/local/libexec/meshtransit
readonly support="/Library/Application Support/MeshTransit"
readonly daemons=/Library/LaunchDaemons
readonly labels=(net.meshtransit.meshnetd net.meshtransit.meshnetd-captive net.meshtransit.meshd)
source_dir=$(cd "$(dirname "$0")" && pwd -P)
readonly source_dir

die() {
	printf 'install: %s\n' "$*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"
[ "$(uname -s)" = Darwin ] || die "this installer is for macOS"
for binary in meshd meshnetd meshcred meshctl; do
	[ -x "$source_dir/$binary" ] || die "$binary is missing next to install.sh"
done
if [ -f "$source_dir/SHA256SUMS" ]; then
	(cd "$source_dir" && shasum -a 256 -c SHA256SUMS --quiet) || die "checksum mismatch"
fi

# A free ID below 500 for a hidden system account and its group.
free_id() {
	local id
	for id in $(seq 400 499); do
		if ! dscl . -search /Users UniqueID "$id" | grep -q . &&
			! dscl . -search /Groups PrimaryGroupID "$id" | grep -q .; then
			echo "$id"
			return 0
		fi
	done
	return 1
}

ensure_group() {
	local name=$1 id
	if ! dscl . -read "/Groups/$name" PrimaryGroupID >/dev/null 2>&1; then
		id=$(free_id) || die "no free group ID for $name"
		dscl . -create "/Groups/$name"
		dscl . -create "/Groups/$name" PrimaryGroupID "$id"
		dscl . -create "/Groups/$name" RealName "MeshTransit"
		dscl . -create "/Groups/$name" Password '*'
	fi
}

ensure_user() {
	if dscl . -read /Users/_meshd UniqueID >/dev/null 2>&1; then
		return
	fi
	local id gid
	id=$(free_id) || die "no free user ID for _meshd"
	gid=$(dscl . -read /Groups/_meshd PrimaryGroupID | awk '{print $2}')
	dscl . -create /Users/_meshd
	dscl . -create /Users/_meshd UniqueID "$id"
	dscl . -create /Users/_meshd PrimaryGroupID "$gid"
	dscl . -create /Users/_meshd UserShell /usr/bin/false
	dscl . -create /Users/_meshd NFSHomeDirectory /var/empty
	dscl . -create /Users/_meshd RealName "MeshTransit daemon"
	dscl . -create /Users/_meshd Password '*'
	dscl . -create /Users/_meshd IsHidden 1
}

ensure_group _meshd
ensure_user
ensure_group meshtransit
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
	dseditgroup -o edit -a "$SUDO_USER" -t user meshtransit
fi

# Stop a running install before replacing its binaries.
for label in "${labels[@]}"; do
	launchctl bootout "system/$label" 2>/dev/null || true
done

install -d -o root -g wheel -m 0755 "$libexec" /usr/local/bin
for binary in meshd meshnetd meshcred; do
	install -o root -g wheel -m 0755 "$source_dir/$binary" "$libexec/$binary"
done
install -o root -g wheel -m 0755 "$source_dir/meshctl" /usr/local/bin/meshctl

install -d -o root -g wheel -m 0755 "$support"
install -d -o _meshd -g _meshd -m 0700 "$support/state"
"$libexec/meshcred" provision

install -d -o root -g wheel -m 0755 /var/log/meshtransit
# launchd opens a job's log as the job's user, so meshd's file must exist and
# belong to _meshd; otherwise launchd refuses to start it (EX_CONFIG).
touch /var/log/meshtransit/meshd.log
chown _meshd:_meshd /var/log/meshtransit/meshd.log
chmod 0640 /var/log/meshtransit/meshd.log
install -o root -g wheel -m 0644 "$source_dir/newsyslog-meshtransit.conf" /etc/newsyslog.d/meshtransit.conf
for label in "${labels[@]}"; do
	install -o root -g wheel -m 0644 "$source_dir/launchd/$label.plist" "$daemons/$label.plist"
	launchctl bootstrap system "$daemons/$label.plist"
done

# meshd starts once meshnetd has made its socket directory.
for _ in $(seq 1 40); do
	[ -S /var/run/meshd/meshd.sock ] && break
	sleep 0.5
done
if [ ! -S /var/run/meshd/meshd.sock ]; then
	printf 'install: meshd did not start; see /var/log/meshtransit/meshd.log and\n' >&2
	printf '         launchctl print system/net.meshtransit.meshd\n' >&2
	exit 1
fi
printf 'MeshTransit is installed and running.\n'
printf 'Connect this Mac with: meshctl up   (log in again first, or use sudo)\n'
