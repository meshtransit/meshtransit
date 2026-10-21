#!/bin/bash
# Removes the MeshTransit client from macOS. Run as root:
#   sudo ./uninstall.sh          keep the identity key and state (reinstall reuses them)
#   sudo ./uninstall.sh --purge  also delete the key, state, logs, user and groups
# The Device stays registered until it is removed in the Console.
set -euo pipefail

readonly labels=(net.meshtransit.meshd net.meshtransit.meshnetd net.meshtransit.meshnetd-captive)
readonly support="/Library/Application Support/MeshTransit"
purge=false
case "${1:-}" in
"") ;;
--purge) purge=true ;;
*)
	printf 'usage: %s [--purge]\n' "$0" >&2
	exit 2
	;;
esac
[ "$(id -u)" -eq 0 ] || {
	printf 'uninstall: run as root: sudo %s\n' "$0" >&2
	exit 1
}

# Stopping meshd destroys its utun links and host routes with it.
for label in "${labels[@]}"; do
	launchctl bootout "system/$label" 2>/dev/null || true
	rm -f "/Library/LaunchDaemons/$label.plist"
done
# A host that used an exit node keeps its pf kill switch and exit routes
# after the helper stops; lift them before the helper goes.
/usr/local/libexec/meshtransit/meshnetd --release-exit 2>/dev/null || true
# meshnetd removes its DNS entries and resolver alias when meshd goes away;
# remove them here too in case it stopped first.
printf 'remove State:/Network/Service/net.meshtransit.dns/DNS\nremove State:/Network/Service/net.meshtransit.dns/IPv4\n' |
	scutil >/dev/null 2>&1 || true
ifconfig lo0 -alias 192.0.2.53 2>/dev/null || true

rm -f /usr/local/bin/meshctl /etc/newsyslog.d/meshtransit.conf
rm -rf /usr/local/libexec/meshtransit /var/run/meshd /var/run/meshnetd

if $purge; then
	rm -rf "$support" /var/log/meshtransit
	dscl . -delete /Users/_meshd 2>/dev/null || true
	dscl . -delete /Groups/_meshd 2>/dev/null || true
	dscl . -delete /Groups/meshtransit 2>/dev/null || true
	printf 'MeshTransit removed, including its identity and state.\n'
else
	printf 'MeshTransit removed. Identity and state kept in %s.\n' "$support"
fi
