#!/bin/sh
set -eu

if [ ! -f /.dockerenv ] || [ "$(id -u)" -ne 0 ]; then
    printf 'this test must run as root in a disposable container\n' >&2
    exit 1
fi

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    printf 'usage: %s PACKAGE\n' "$0" >&2
    exit 2
fi

for path in /etc/credstore.encrypted /etc/meshd /run/meshd /run/meshnetd /run/systemd/system /var/lib/meshd; do
    if [ -e "${path}" ]; then
        printf 'container path is not clean: %s\n' "${path}" >&2
        exit 1
    fi
done

package_path="$1"
work_dir="$(mktemp -d)"
control_dir="${work_dir}/control"
mock_bin="${work_dir}/bin"
service_calls="${work_dir}/service-calls"
cleanup() {
    rm -rf -- /etc/credstore.encrypted /etc/meshd /run/meshd /run/meshnetd /var/lib/meshd "${work_dir}"
    rmdir -- /run/systemd/system /run/systemd 2>/dev/null || true
}
trap cleanup EXIT

dpkg-deb --control "${package_path}" "${control_dir}"
mkdir -p "${mock_bin}" /etc/meshd /run/systemd/system

cat >"${mock_bin}/record-command" <<'EOF'
#!/bin/sh
exit 0
EOF

cat >"${mock_bin}/deb-systemd-helper" <<'EOF'
#!/bin/sh
if [ "${1:-}" = debian-installed ]; then
    exit 0
fi
exit 0
EOF

cat >"${mock_bin}/systemctl" <<'EOF'
#!/bin/sh
case " $* " in
    *" is-active "*)
        if [ "${MESHD_TEST_ACTIVE:-true}" = true ]; then
            exit 0
        fi
        exit 3
        ;;
esac
exit 0
EOF

cat >"${mock_bin}/deb-systemd-invoke" <<'EOF'
#!/bin/sh
printf 'deb-systemd-invoke' >>"${MESHD_TEST_SERVICE_CALLS}"
for argument in "$@"; do
    printf ' <%s>' "${argument}" >>"${MESHD_TEST_SERVICE_CALLS}"
done
printf '\n' >>"${MESHD_TEST_SERVICE_CALLS}"
EOF

chmod 0755 \
    "${mock_bin}/record-command" \
    "${mock_bin}/deb-systemd-helper" \
    "${mock_bin}/systemctl" \
    "${mock_bin}/deb-systemd-invoke"
ln -s record-command "${mock_bin}/systemd-sysusers"
ln -s record-command "${mock_bin}/systemd-tmpfiles"
export MESHD_TEST_SERVICE_CALLS="${service_calls}"
export PATH="${mock_bin}:${PATH}"

: >"${service_calls}"
"${control_dir}/postinst" configure
grep -Fqx 'deb-systemd-invoke <start> <meshnetd.service> <meshd.service>' \
    "${service_calls}"

mkdir -p /etc/credstore.encrypted /run/meshd /run/meshnetd /var/lib/meshd/identities
touch \
    /etc/credstore.encrypted/meshd.identity-key \
    /etc/credstore.encrypted/meshd.identity-key.recovery \
    /etc/meshd/meshd.env \
    /run/meshd/meshd.sock \
    /run/meshnetd/meshnetd.sock \
    /var/lib/meshd/profiles.json \
    /var/lib/meshd/identities/node.json

: >"${service_calls}"
MESHD_TEST_ACTIVE=true "${control_dir}/prerm" remove
grep -Fqx 'deb-systemd-invoke <stop> <meshd.service> <meshnetd.service> <meshcred.service>' \
    "${service_calls}"
[ -f /etc/meshd/.start-on-reinstall ]

"${control_dir}/postrm" remove
[ ! -e /run/meshd ]
[ ! -e /run/meshnetd ]
[ -f /var/lib/meshd/profiles.json ]
[ -f /etc/meshd/meshd.env ]
[ -f /etc/credstore.encrypted/meshd.identity-key ]
[ -f /etc/credstore.encrypted/meshd.identity-key.recovery ]

: >"${service_calls}"
"${control_dir}/postinst" configure 0.1.0~previous
grep -Fqx 'deb-systemd-invoke <start> <meshnetd.service> <meshd.service>' \
    "${service_calls}"
if grep -Fq '<try-restart>' "${service_calls}"; then
    printf 'running service reinstall used try-restart\n' >&2
    exit 1
fi
[ ! -e /etc/meshd/.start-on-reinstall ]

mkdir -p /run/meshd /run/meshnetd
touch /run/meshd/meshd.sock /run/meshnetd/meshnetd.sock
: >"${service_calls}"
MESHD_TEST_ACTIVE=false "${control_dir}/prerm" remove
[ ! -e /etc/meshd/.start-on-reinstall ]
"${control_dir}/postrm" remove

: >"${service_calls}"
"${control_dir}/postinst" configure 0.1.0~previous
grep -Fqx 'deb-systemd-invoke <try-restart> <meshnetd.service> <meshd.service>' \
    "${service_calls}"

mkdir -p /run/meshd /run/meshnetd
touch /etc/meshd/.start-on-reinstall /run/meshd/stale /run/meshnetd/stale
"${control_dir}/postrm" purge
[ ! -e /var/lib/meshd ]
[ ! -e /run/meshd ]
[ ! -e /run/meshnetd ]
[ ! -e /etc/meshd/.start-on-reinstall ]
[ ! -e /etc/credstore.encrypted/meshd.identity-key ]
[ ! -e /etc/credstore.encrypted/meshd.identity-key.recovery ]
[ -f /etc/meshd/meshd.env ]

printf 'package maintainer lifecycle verified\n'
