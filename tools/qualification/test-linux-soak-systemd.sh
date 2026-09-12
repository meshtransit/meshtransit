#!/usr/bin/env bash

set -Eeuo pipefail

export LC_ALL=C

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly launcher="${script_dir}/linux-soak-systemd.sh"

test_dir=""
cleanup() {
  if [[ -n "${test_dir}" ]]; then
    rm -f -- "${test_dir}/bin/systemctl"
    rmdir -- "${test_dir}/bin" "${test_dir}"
  fi
}
trap cleanup EXIT

help_output="$("${launcher}" --help)"
grep -Fq -- 'Starts one protected transient systemd observer' <<<"${help_output}"
grep -Fq -- 'RefuseManualStop=yes' <<<"${help_output}"
grep -Fq -- 'failure cannot silently create a fresh evidence window' <<<"${help_output}"

rendered="$("${launcher}" __render-systemd-command \
  meshtransit-soak-linux-rc1-a.service \
  /root/meshtransit-qualification/linux-rc1-a/report.json \
  /root/meshtransit-qualification/linux-rc1-a/stderr.log \
  /root/meshtransit-qualification/linux-rc1-a/linux-soak.sh \
  /root/meshtransit-qualification/linux-rc1-a \
  262800 \
  --node-label ubuntu-a \
  --artifact-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)"

for expected in \
  '--property=RefuseManualStop=yes' \
  '--property=Restart=no' \
  '--property=RuntimeMaxSec=262800s' \
  '--property=ProtectSystem=strict' \
  '--property=ProtectHome=read-only' \
  '--property=NoNewPrivileges=yes' \
  '--property=StandardOutput=file:/root/meshtransit-qualification/linux-rc1-a/report.json' \
  '--property=StandardError=file:/root/meshtransit-qualification/linux-rc1-a/stderr.log' \
  '/root/meshtransit-qualification/linux-rc1-a/linux-soak.sh' \
  '--node-label' \
  'ubuntu-a'; do
  grep -Fxq -- "${expected}" <<<"${rendered}"
done

[[ "$(grep -Fxc -- '--property=RefuseManualStop=yes' <<<"${rendered}")" == 1 ]]
[[ "$(grep -Fxc -- '--property=Restart=no' <<<"${rendered}")" == 1 ]]

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshd-linux-soak-systemd-test.XXXXXXXX")"
mkdir -- "${test_dir}/bin"
cat >"${test_dir}/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
case "${UNIT_LOAD_STATE:-not-found}" in
  error) exit 1 ;;
  *) printf '%s\n' "${UNIT_LOAD_STATE:-not-found}" ;;
esac
EOF
chmod 0755 "${test_dir}/bin/systemctl"

PATH="${test_dir}/bin:${PATH}" UNIT_LOAD_STATE=not-found \
  "${launcher}" __require-unit-absent meshtransit-soak-linux-rc1-a.service
if PATH="${test_dir}/bin:${PATH}" UNIT_LOAD_STATE=loaded \
  "${launcher}" __require-unit-absent meshtransit-soak-linux-rc1-a.service >/dev/null 2>&1; then
  printf 'loaded unit unexpectedly passed absence check\n' >&2
  exit 1
fi
if PATH="${test_dir}/bin:${PATH}" UNIT_LOAD_STATE=error \
  "${launcher}" __require-unit-absent meshtransit-soak-linux-rc1-a.service >/dev/null 2>&1; then
  printf 'failed systemd query unexpectedly passed absence check\n' >&2
  exit 1
fi

printf 'linux soak systemd launcher validation passed\n'
