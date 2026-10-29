#!/usr/bin/env bash
# Checks the chart: lint, render, refusals, invariants, and, given a kube
# context, a server dry-run of the cluster-wide guards (K1c design §6, Q90).
#   ci/check.sh [kube-context]
set -euo pipefail
cd "$(dirname "$0")/.."
ns=mt-kube-k1
base=ci/values-lab.yaml
render() { helm template kg . -n "$ns" -f "$base" "$@"; }

helm lint . --strict -f "$base" --namespace "$ns" >/dev/null
render >/dev/null
render -f ci/values-enforced.yaml >/dev/null
echo "renders: ok"

# Every case must be refused at render time.
refused=0
refuse() {
  local name="$1"; shift
  if render "$@" >/dev/null 2>&1; then echo "NOT REFUSED: $name" >&2; refused=1; fi
}
refuse "no cluster" --set cluster=
refuse "cluster too long" --set cluster=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
refuse "http control" --set control.url=http://control.meshtransit.net
refuse "control with path" --set control.url=https://control.meshtransit.net/x
refuse "bad fingerprint" --set control.fingerprint=sha256:00
refuse "tag without allowTag" --set image.digest= --set image.tag=x
refuse "no audiences" --set 'apiServerAudiences=null'
refuse "audience as JSON" --set 'apiServerAudiences[0]=["a"]'
refuse "no memory limit" --set resources.limits.memory=null
refuse "burstable memory" --set resources.requests.memory=256Mi
refuse "two defaults" --set 'groups[1].name=x' --set 'groups[1].clusterRole=view' --set 'groups[1].default=true'
refuse "privileged default" --set 'groups[0].privileged=true' --set 'groups[0].allowedPrincipals[0]=p'
refuse "cluster-admin unprivileged" --set 'groups[0].clusterRole=cluster-admin'
refuse "edit across the cluster" --set 'groups[1].clusterRole=edit' --set 'groups[1].namespaces=null'
refuse "rights in kube-system" --set 'groups[1].namespaces[0]=kube-system'
refuse "rights in the gateway namespace" --set "groups[1].namespaces[0]=$ns"
refuse "principals unprivileged" --set 'groups[0].allowedPrincipals[0]=p'
refuse "privileged without principals" --set 'groups[1].privileged=true'
refuse "no kube-system" --set 'nodeLevelNamespaces[0]=local-path-storage' --set 'nodeLevelNamespaces[1]=x'
refuse "gateway namespace node-level" --set "nodeLevelNamespaces[2]=$ns"
refuse "enforce without pool" --set gatewayPool.enabled=false --set placement.enforce=true
refuse "buffer too small" --set network.tcpSendBufferBytes=1024
refuse "stale too short" --set staleAfterSeconds=60
refuse "six replicas" --set replicas=6
refuse "unknown value" --set surprise=1
refuse "fullname not a label" --set fullnameOverride=Mesh_GW
refuse "quote in repository" --set "image.repository=a'b"
refuse "backslash audience" --set-json 'apiServerAudiences=["a\\\\b"]'
refuse "repeated namespace" --set 'groups[1].namespaces[1]=default'
[[ $refused == 0 ]] || exit 1
echo "refusals: ok"

# Invariants: state Secrets carry no data (Q80); the exempt list and the
# guarded namespaces come from one value (Q76).
out=$(render)
if printf '%s' "$out" | awk '/^kind: Secret/{s=1} /^---/{s=0} s && /^(data|stringData):/{f=1} END{exit !f}'; then
  echo "a state Secret renders data" >&2; exit 1
fi
printf '%s' "$out" | grep -q 'MESHGW_GUARDED_NAMESPACES: "local-path-storage"' || { echo "guarded namespaces" >&2; exit 1; }
printf '%s' "$out" | grep -q 'values: \["mt-kube-k1","kube-system","local-path-storage"\]' || { echo "placement exempt" >&2; exit 1; }
printf '%s' "$out" | grep -q 'values: \["kube-system","local-path-storage"\]' || { echo "binding exempt" >&2; exit 1; }
render --set-json 'network.tcpSendBufferBytes=4194304' | grep -q 'MESHGW_TCP_SEND_BUFFER: "4194304"' || { echo "buffer not an integer" >&2; exit 1; }
# The gateway's selectors leave the check's pods out (review c3 H1).
[[ $(printf '%s' "$out" | grep -c 'app.kubernetes.io/component: gateway') -ge 6 ]] || { echo "gateway selectors" >&2; exit 1; }
echo "invariants: ok"

if [[ $# -eq 1 ]]; then
  render | python3 -I -c 'import sys; print("\n---\n".join(d for d in sys.stdin.read().split("\n---\n") if "ValidatingAdmissionPolic" in d or "FlowSchema" in d or "PriorityLevel" in d))' |
    kubectl --context "$1" apply --dry-run=server -f - >/dev/null
  echo "server dry-run: ok"
fi
if command -v trivy >/dev/null; then
  rendered=$(mktemp); render > "$rendered"
  trivy config --severity HIGH,CRITICAL --exit-code 1 --quiet --ignorefile ci/trivyignore "$rendered"
  echo "trivy: ok"
fi
