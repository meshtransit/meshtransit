#!/usr/bin/env bash
# V1-22 step 3: run the broker's sign-in against a real Keycloak.
#
# Keycloak serves TLS from a throwaway CA on port 8443 of a private docker
# network; the dexbroker E2E test binary (cross-compiled here) runs on the
# same network, since the broker never reaches loopback. Everything is torn
# down at exit.
#
#   GOWORK=<dex workspace> core/test/e2e/keycloak/run.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../../.." && pwd)"
keycloak_image="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.4.5}"
runner_image="${RUNNER_IMAGE:-localhost:5001/golang:1.26.11-bookworm}"
network="mt-v122-oidc"
subnet="172.31.250.0/24"
work="$(mktemp -d)"
arch="$(docker version --format '{{.Server.Arch}}')"

cleanup() {
  docker rm -f mt-v122-keycloak >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

: "${GOWORK:?set GOWORK to the Dex workspace (dexbroker build)}"

# Throwaway CA and server certificate for "keycloak".
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=MeshTransit E2E CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
  -keyout "$work/ca.key" -out "$work/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=keycloak" \
  -keyout "$work/tls.key" -out "$work/tls.csr" 2>/dev/null
printf 'subjectAltName=DNS:keycloak\nextendedKeyUsage=serverAuth\n' >"$work/ext"
openssl x509 -req -in "$work/tls.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" -CAcreateserial -days 1 \
  -extfile "$work/ext" -out "$work/tls.crt" 2>/dev/null
chmod 0644 "$work/tls.key" "$work/tls.crt" "$work/ca.pem"

client_secret="$(openssl rand -hex 24)"
password="$(openssl rand -hex 12)"
printf '%s\n' "$client_secret" >"$work/client-secret"
chmod 0644 "$work/client-secret"
mkdir -p "$work/import"
sed -e "s/@CLIENT_SECRET@/$client_secret/" -e "s/@PASSWORD@/$password/g" "$here/realm.json.tmpl" >"$work/import/corp.json"
chmod 0755 "$work/import"; chmod 0644 "$work/import/corp.json"

(cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -tags=dexbroker,keycloake2e \
  -o "$work/dexbroker.test" ./core/internal/adapter/dexbroker)

docker network create --subnet "$subnet" "$network" >/dev/null
docker run -d --name mt-v122-keycloak --network "$network" --network-alias keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -hex 12)" \
  -v "$work:/certs:ro" -v "$work/import:/opt/keycloak/data/import:ro" \
  "$keycloak_image" start-dev --import-realm --http-enabled=false --https-port=8443 \
  --https-certificate-file=/certs/tls.crt --https-certificate-key-file=/certs/tls.key \
  --hostname=https://keycloak:8443 >/dev/null

echo "waiting for Keycloak"
for _ in $(seq 1 90); do
  if docker run --rm --network "$network" -v "$work:/e2e:ro" "$runner_image" \
    curl -sf --cacert /e2e/ca.pem https://keycloak:8443/realms/corp/.well-known/openid-configuration >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

docker run --rm --network "$network" -v "$work:/e2e:ro" \
  -e KC_ISSUER=https://keycloak:8443/realms/corp -e KC_CA_FILE=/e2e/ca.pem -e KC_CIDR="$subnet" \
  -e KC_CLIENT_SECRET_FILE=/e2e/client-secret -e KC_PASSWORD="$password" \
  -e KC_ID_ALICE=4f2c0d4e-0000-4000-8000-000000000001 -e KC_ID_BOB=4f2c0d4e-0000-4000-8000-000000000002 \
  "$runner_image" /e2e/dexbroker.test -test.v -test.count=1 -test.run 'Keycloak' "$@"
