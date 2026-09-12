#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# -eq 1 ]] || {
    printf 'usage: %s TARGET_DIRECTORY\n' "$0" >&2
    exit 2
}

readonly target_dir="$1"
readonly syft_version='1.51.1'
readonly grype_version='0.116.1'

for tool in awk curl install mktemp rm tar uname; do
    command -v "${tool}" >/dev/null || {
        printf 'required tool is unavailable: %s\n' "${tool}" >&2
        exit 1
    }
done

case "$(uname -s)" in
    Darwin) platform='darwin' ;;
    Linux) platform='linux' ;;
    *)
        printf 'unsupported operating system: %s\n' "$(uname -s)" >&2
        exit 1
        ;;
esac
readonly platform

case "$(uname -m)" in
    arm64|aarch64) architecture='arm64' ;;
    x86_64|amd64) architecture='amd64' ;;
    *)
        printf 'unsupported architecture: %s\n' "$(uname -m)" >&2
        exit 1
        ;;
esac
readonly architecture

case "${platform}_${architecture}" in
    darwin_amd64)
        readonly syft_sha256='0e186ce1d4351ec276126851ca3ff258ed070e93e73574ed64858d4fc2339867'
        readonly grype_sha256='e5ff3adac317511876de7863598587a7dbab0c47c8e150368b7df06909c11f4e'
        ;;
    darwin_arm64)
        readonly syft_sha256='ac063af3b9874769deb7ea1e6d76841e68f9e3bb50cd654226fc977de65532c1'
        readonly grype_sha256='f493f169cbaae48bade169532b20235fc16653d2a044a5bc6fe6f69a3923f975'
        ;;
    linux_amd64)
        readonly syft_sha256='8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3'
        readonly grype_sha256='0122df7b655981abe547ad3d2190d65551dac6a2bfc80b4dc2a989b5d0587458'
        ;;
    linux_arm64)
        readonly syft_sha256='a7fd2b784e6664acd44719270574f6cd8c6864fc2b1700bf9099bd1cccda7d7f'
        readonly grype_sha256='a8d7504a149629324eb5f4ce3dc25dfd211bbfe047e64ee2bf7844b466c3d84d'
        ;;
esac

sha256_digest() {
    local path="$1"

    if command -v sha256sum >/dev/null && sha256sum --version >/dev/null 2>&1; then
        sha256sum "${path}" | awk '{print $1}'
        return
    fi
    if command -v shasum >/dev/null; then
        shasum -a 256 "${path}" | awk '{print $1}'
        return
    fi
    printf 'a SHA-256 utility is required\n' >&2
    return 1
}

work_dir="$(mktemp -d)"
readonly work_dir
cleanup() {
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

install_tool() {
    local name="$1"
    local version="$2"
    local expected_sha256="$3"
    local archive="${work_dir}/${name}.tar.gz"
    local url="https://github.com/anchore/${name}/releases/download/v${version}/${name}_${version}_${platform}_${architecture}.tar.gz"

    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        --retry 3 --output "${archive}" "${url}"

    local actual_sha256
    actual_sha256="$(sha256_digest "${archive}")"
    if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
        printf '%s archive checksum mismatch\n' "${name}" >&2
        return 1
    fi

    tar -xzf "${archive}" -C "${work_dir}" "${name}"
    install -m 0755 "${work_dir}/${name}" "${target_dir}/${name}"
    local installed_version
    installed_version="$(
        "${target_dir}/${name}" version 2>&1 |
            awk '$1 == "Version:" {print $2; exit}'
    )"
    [[ "${installed_version}" == "${version}" ]] || {
        printf '%s reported unexpected version: %s\n' \
            "${name}" "${installed_version}" >&2
        return 1
    }
    rm -f -- "${archive}" "${work_dir}/${name}"
}

install -d -m 0755 "${target_dir}"
install_tool syft "${syft_version}" "${syft_sha256}"
install_tool grype "${grype_version}" "${grype_sha256}"

printf 'installed syft %s and grype %s in %s\n' \
    "${syft_version}" "${grype_version}" "${target_dir}"
