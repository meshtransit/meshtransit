#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# -eq 1 ]] || {
    printf 'usage: %s PACKAGE\n' "$0" >&2
    exit 2
}

readonly package_path="$1"
readonly sbom_path="${package_path}.cdx.json"
readonly report_path="${package_path}.grype.json"
readonly syft_version='1.51.1'
readonly grype_version='0.116.1'

[[ -f "${package_path}" ]] || {
    printf 'package does not exist: %s\n' "${package_path}" >&2
    exit 1
}
[[ -f "${package_path}.sha256" ]] || {
    printf 'package checksum does not exist: %s.sha256\n' "${package_path}" >&2
    exit 1
}

for tool in awk basename dirname dpkg-deb go grep jq mkdir mktemp mv rm sha256sum sort syft grype; do
    command -v "${tool}" >/dev/null || {
        printf 'required tool is unavailable: %s\n' "${tool}" >&2
        exit 1
    }
done

installed_syft_version="$(
    syft version 2>&1 | awk '$1 == "Version:" {print $2; exit}'
)"
readonly installed_syft_version
[[ "${installed_syft_version}" == "${syft_version}" ]] || {
    printf 'syft %s is required\n' "${syft_version}" >&2
    exit 1
}
installed_grype_version="$(
    grype version 2>&1 | awk '$1 == "Version:" {print $2; exit}'
)"
readonly installed_grype_version
[[ "${installed_grype_version}" == "${grype_version}" ]] || {
    printf 'grype %s is required\n' "${grype_version}" >&2
    exit 1
}

checksum_line_count="$(awk 'END {print NR}' "${package_path}.sha256")"
readonly checksum_line_count
[[ "${checksum_line_count}" == 1 ]] || {
    printf 'package checksum must contain exactly one record\n' >&2
    exit 1
}
IFS=' ' read -r expected_package_sha256 checksum_filename trailing \
    <"${package_path}.sha256"
readonly expected_package_sha256 checksum_filename trailing
[[ "${expected_package_sha256}" =~ ^[0-9a-f]{64}$ ]] || {
    printf 'package checksum digest is invalid\n' >&2
    exit 1
}
[[ "${checksum_filename}" == "$(basename "${package_path}")" && -z "${trailing}" ]] || {
    printf 'package checksum references an unexpected file\n' >&2
    exit 1
}
actual_package_sha256="$(sha256sum "${package_path}" | awk '{print $1}')"
readonly actual_package_sha256
[[ "${actual_package_sha256}" == "${expected_package_sha256}" ]] || {
    printf 'package checksum mismatch\n' >&2
    exit 1
}
printf '%s: OK\n' "$(basename "${package_path}")"

package_name="$(dpkg-deb --field "${package_path}" Package)"
readonly package_name
package_version="$(dpkg-deb --field "${package_path}" Version)"
readonly package_version
package_architecture="$(dpkg-deb --field "${package_path}" Architecture)"
readonly package_architecture
package_commit="$(dpkg-deb --field "${package_path}" X-MeshTransit-Commit)"
readonly package_commit
package_build_date="$(dpkg-deb --field "${package_path}" X-MeshTransit-Build-Date)"
readonly package_build_date
package_filename="$(basename "${package_path}")"
readonly package_filename
package_sha256="${actual_package_sha256}"
readonly package_sha256

[[ "${package_name}" == 'meshd' ]] || {
    printf 'unexpected package name: %s\n' "${package_name}" >&2
    exit 1
}
[[ "${package_architecture}" == 'amd64' || "${package_architecture}" == 'arm64' ]] || {
    printf 'unsupported package architecture: %s\n' "${package_architecture}" >&2
    exit 1
}
[[ "${package_commit}" =~ ^[0-9a-f]{40}$ ]] || {
    printf 'package commit metadata is invalid\n' >&2
    exit 1
}
[[ "${package_build_date}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || {
    printf 'package build date metadata is invalid\n' >&2
    exit 1
}

work_dir="$(mktemp -d)"
readonly work_dir
cleanup() {
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

readonly package_root="${work_dir}/root"
readonly raw_cyclonedx="${work_dir}/raw.cdx.json"
readonly native_sbom="${work_dir}/scan.syft.json"
readonly normalized_cyclonedx="${work_dir}/normalized.cdx.json"
readonly raw_report="${work_dir}/raw.grype.json"
readonly normalized_report="${work_dir}/normalized.grype.json"
mkdir -p "${package_root}"
dpkg-deb --extract "${package_path}" "${package_root}"

readonly -a packaged_binaries=(
    '/usr/bin/meshd'
    '/usr/libexec/meshtransit/meshnetd'
    '/usr/libexec/meshtransit/meshcred'
)
for binary in "${packaged_binaries[@]}"; do
    [[ -x "${package_root}${binary}" ]] || {
        printf 'expected packaged binary is missing: %s\n' "${binary}" >&2
        exit 1
    }
done

SYFT_CHECK_FOR_APP_UPDATE=false \
SYFT_LOG_QUIET=true \
SYFT_GOLANG_CAPTURE_SYMBOLS=all \
    syft scan "dir:${package_root}" \
        --base-path "${package_root}" \
        --source-name meshd \
        --source-supplier MeshTransit \
        --source-version "${package_version}" \
        --output "cyclonedx-json=${raw_cyclonedx}" \
        --output "syft-json=${native_sbom}"

jq -e '
    .descriptor.configuration.packages.golang["capture-symbols"] == "all"
    and any(.artifacts[];
        .type == "go-module"
        and ((.metadata.symbols? // {}) | length) > 0)
' "${native_sbom}" >/dev/null || {
    printf 'native SBOM does not contain Go function symbols\n' >&2
    exit 1
}

jq --sort-keys \
    --arg root "${package_root}" \
    --arg version "${package_version}" \
    --arg architecture "${package_architecture}" \
    --arg commit "${package_commit}" \
    --arg build_date "${package_build_date}" \
    --arg filename "${package_filename}" \
    --arg sha256 "${package_sha256}" '
        ($version | @uri) as $purl_version
        | del(.serialNumber)
        | .metadata.timestamp = $build_date
        | .metadata.component = {
            "bom-ref": ("pkg:deb/meshd@" + $purl_version + "?arch=" + $architecture),
            "type": "application",
            "group": "meshtransit",
            "name": "meshd",
            "version": $version,
            "hashes": [{"alg": "SHA-256", "content": $sha256}],
            "purl": ("pkg:deb/meshd@" + $purl_version + "?arch=" + $architecture),
            "externalReferences": [{
                "type": "vcs",
                "url": ("https://github.com/meshtransit/meshd/commit/" + $commit)
            }],
            "properties": [
                {"name": "meshtransit:artifact:filename", "value": $filename},
                {"name": "meshtransit:artifact:architecture", "value": $architecture},
                {"name": "meshtransit:artifact:git-commit", "value": $commit}
            ]
        }
        | .components |= map(
            if .name == "github.com/meshtransit/meshd" and .version == "UNKNOWN" then
                .version = $version
                | .purl = ("pkg:golang/github.com/meshtransit/meshd@" + $purl_version)
                | del(.cpe)
            elif .type == "file" and (.name | startswith($root + "/")) then
                .name = (.name | ltrimstr($root))
            else . end
        )
    ' "${raw_cyclonedx}" >"${normalized_cyclonedx}"

jq -e \
    --arg version "${package_version}" \
    --arg architecture "${package_architecture}" \
    --arg commit "${package_commit}" \
    --arg filename "${package_filename}" \
    --arg sha256 "${package_sha256}" \
    --arg syft_version "${syft_version}" '
        .bomFormat == "CycloneDX"
        and .specVersion == "1.7"
        and .metadata.component.type == "application"
        and .metadata.component.name == "meshd"
        and .metadata.component.version == $version
        and any(.metadata.component.hashes[];
            .alg == "SHA-256" and .content == $sha256)
        and any(.metadata.component.properties[];
            .name == "meshtransit:artifact:filename" and .value == $filename)
        and any(.metadata.component.properties[];
            .name == "meshtransit:artifact:architecture" and .value == $architecture)
        and any(.metadata.component.properties[];
            .name == "meshtransit:artifact:git-commit" and .value == $commit)
        and any(.metadata.tools.components[];
            .name == "syft" and .version == $syft_version)
        and any(.components[];
            ((.purl // "") | startswith("pkg:golang/")))
        and all(.components[];
            .name != "github.com/meshtransit/meshd" or .version == $version)
    ' "${normalized_cyclonedx}" >/dev/null

for binary in "${packaged_binaries[@]}"; do
    jq -e --arg path "${binary}" '
        any(.components[].properties[]?;
            (.name | test("^syft:location:[0-9]+:path$")) and .value == $path)
    ' "${normalized_cyclonedx}" >/dev/null || {
        printf 'SBOM does not inventory packaged binary: %s\n' "${binary}" >&2
        exit 1
    }
done

while IFS=$'\t' read -r module version; do
    [[ -n "${module}" && -n "${version}" ]] || continue
    jq -e --arg module "${module}" --arg version "${version}" '
        any(.components[]; .name == $module and .version == $version)
    ' "${normalized_cyclonedx}" >/dev/null || {
        printf 'SBOM is missing runtime module %s %s\n' "${module}" "${version}" >&2
        exit 1
    }
done < <(
    for binary in "${packaged_binaries[@]}"; do
        go version -m "${package_root}${binary}"
    done | awk '$1 == "dep" {print $2 "\t" $3}' | sort -u
)

while IFS= read -r location; do
    [[ "${location}" == /* && -e "${package_root}${location}" ]] || {
        printf 'SBOM contains a location outside the package: %s\n' "${location}" >&2
        exit 1
    }
done < <(
    jq -r '[.components[].properties[]?
        | select(.name | test("^syft:location:[0-9]+:path$"))
        | .value] | unique[]' "${normalized_cyclonedx}"
)

if grep -Fq "${package_root}" "${normalized_cyclonedx}"; then
    printf 'SBOM contains its temporary extraction path\n' >&2
    exit 1
fi

GRYPE_CHECK_FOR_APP_UPDATE=false \
    grype "sbom:${native_sbom}" --output json --file "${raw_report}"

jq --sort-keys \
    --arg filename "${package_filename}" \
    --arg grype_version "${grype_version}" '
        .source.target = $filename
        | .source.type = "file"
        | .descriptor.version = $grype_version
        | del(.descriptor.configuration)
        | del(.descriptor.db.status.path)
    ' "${raw_report}" >"${normalized_report}"

if grep -Eq '/(home/runner|Users|private/var/folders|tmp)/' \
    "${normalized_report}"; then
    printf 'vulnerability report contains a local build path\n' >&2
    exit 1
fi

mv "${normalized_cyclonedx}" "${sbom_path}"
mv "${normalized_report}" "${report_path}"
(
    cd "$(dirname "${package_path}")"
    sha256sum "$(basename "${sbom_path}")" >"$(basename "${sbom_path}").sha256"
    sha256sum "$(basename "${report_path}")" >"$(basename "${report_path}").sha256"
)

GRYPE_CHECK_FOR_APP_UPDATE=false \
    grype "sbom:${native_sbom}" --fail-on high --output table

printf 'audited %s\n' "${package_path}"
printf 'SBOM: %s\n' "${sbom_path}"
printf 'vulnerability report: %s\n' "${report_path}"
