#!/usr/bin/env bash
# Runs real requests through the chart's admission policies on a cluster
# where it is installed. Creating a policy only type-checks its CEL; a
# runtime error (reading a field a request lacks) makes a fail-closed policy
# refuse everything it matches (K1c c4), and shows here as cel-error, never
# as a pass. Pods are created with a server dry-run, except one plain pod in
# default for the update cases, deleted at the end.
#   ci/cases.sh <namespace> <fullname> <kubectl command...>
#   DISRUPTIVE=1 also deletes replica 1 and waits for its replacement.
# e.g. ci/cases.sh mt-kube-k1 meshgw kubectl --context kind-x
set -uo pipefail
if (( $# < 3 )); then
  echo "usage: $0 <namespace> <fullname> <kubectl command...>" >&2
  exit 2
fi
ns="$1"; fullname="$2"; shift 2
kc=("$@")
prefix=meshtransit-kube-gateway
gateway="$fullname-0"
group=$("${kc[@]}" -n "$ns" get serviceaccounts -l app.kubernetes.io/part-of=meshtransit-kube-gateway -o name |
  sed -n 's|^serviceaccount/\(mt-.*\)|\1|p' | head -1)
mode() {
  local actions
  if ! actions=$("${kc[@]}" get validatingadmissionpolicybinding "$prefix-$1" -o jsonpath='{.spec.validationActions}'); then
    echo "binding $prefix-$1 is missing" >&2
    exit 2
  fi
  grep -q Deny <<<"$actions" && echo deny || echo warn
}
broad=$(mode placement-broad)
binding=$(mode binding)
failed=0

# Each policy's own messages: a deny or warn counts only with one of them,
# so an error in a match condition, which shows under the same prefix,
# never passes (review c4).
message() {
  case "$1" in
    placement-target) echo "pods here may not tolerate the gateway pool's taint or select the gateway pool" ;;
    placement-broad) echo "pods here may not (name a node|tolerate every taint)" ;;
    binding) echo "only the scheduler binds pods to nodes here" ;;
    namespace) echo "(in the gateway's namespace only|images do not change in place|no ephemeral containers|no exec, attach)" ;;
    token-others) echo "only the gateway mints its groups' tokens" ;;
  esac
}

# expect <want> <policy> <name> <command...>: deny and warn count only from
# the named policy; any CEL runtime error fails the case.
expect() {
  local want="$1" policy="$2" name="$3"; shift 3
  local out code got
  out=$("$@" 2>&1); code=$?
  local said; said=$(message "$policy")
  if grep -qE 'resulted in (an )?error|no such key|evaluation error' <<<"$out"; then got=cel-error
  elif grep -qE "ValidatingAdmissionPolicy '$prefix-$policy' with binding '[^']*' denied request: $said" <<<"$out"; then got=deny
  elif grep -qE "Validation failed for ValidatingAdmissionPolicy '$prefix-$policy' with binding '[^']*': $said" <<<"$out"; then
    got=warn
  elif [[ $code -ne 0 && $want != allow-error ]]; then got="error: $(head -c 200 <<<"$out")"
  else got=allow; fi
  [[ $want == allow-error ]] && want=allow
  if [[ $got == "$want" ]]; then echo "ok    $name ($got)"; else echo "FAIL  $name: want $want, got $got"; failed=1; fi
}

# A restricted pod named $1 in $2, with more spec lines in $3.
pod() {
  printf 'apiVersion: v1\nkind: Pod\nmetadata: {name: %s, namespace: %s}\nspec:\n  securityContext: {runAsNonRoot: true, runAsUser: 65532, seccompProfile: {type: RuntimeDefault}}\n  containers: [{name: p, image: registry.k8s.io/pause:3.10, securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}}]\n%s' "$1" "$2" "$3"
}
try_pod() { pod "$1" "$2" "$3" | "${kc[@]}" create --dry-run=server -f -; }

# Placement: targeting the pool is always refused outside exempt namespaces.
expect deny placement-target "toleration of the pool's taint" try_pod c4-a default '  tolerations: [{key: meshtransit.net/gateway, operator: Exists}]
'
expect deny placement-target "pool label in nodeSelector" try_pod c4-b default '  nodeSelector: {node-restriction.kubernetes.io/meshtransit-gateway-pool: x}
'
expect deny placement-target "required affinity In the pool" try_pod c4-c default '  affinity: {nodeAffinity: {requiredDuringSchedulingIgnoredDuringExecution: {nodeSelectorTerms: [{matchExpressions: [{key: node-restriction.kubernetes.io/meshtransit-gateway-pool, operator: In, values: [x]}]}]}}}
'
expect deny placement-target "preferred affinity for the pool" try_pod c4-d default '  affinity: {nodeAffinity: {preferredDuringSchedulingIgnoredDuringExecution: [{weight: 1, preference: {matchExpressions: [{key: node-restriction.kubernetes.io/meshtransit-gateway-pool, operator: Exists}]}}]}}
'
expect allow placement-target "affinity avoiding the pool" try_pod c4-e default '  affinity: {nodeAffinity: {requiredDuringSchedulingIgnoredDuringExecution: {nodeSelectorTerms: [{matchExpressions: [{key: node-restriction.kubernetes.io/meshtransit-gateway-pool, operator: DoesNotExist}]}]}}}
'
expect allow placement-target "pool toleration in kube-system (exempt)" try_pod c4-f kube-system '  tolerations: [{key: meshtransit.net/gateway, operator: Exists}]
'
expect "$broad" placement-broad "tolerating every taint" try_pod c4-g default '  tolerations: [{operator: Exists}]
'
expect "$broad" placement-broad "naming a node" try_pod c4-h default '  nodeName: none-such
'
expect allow placement-target "a plain pod" try_pod c4-i default ''

# Updates reach the policies' oldObject branches.
pod c4-plain default '' | "${kc[@]}" create -f - >/dev/null 2>&1
trap '"${kc[@]}" delete pod -n default c4-plain --ignore-not-found --wait=false >/dev/null 2>&1' EXIT
expect allow placement-target "labelling a plain pod" "${kc[@]}" -n default label pod/c4-plain c4-case=1 --dry-run=server
expect deny placement-target "adding the pool's toleration" "${kc[@]}" -n default patch pod/c4-plain --type=json \
  --dry-run=server -p '[{"op":"add","path":"/spec/tolerations/-","value":{"key":"meshtransit.net/gateway","operator":"Exists"}}]'
binder() {
  printf '{"apiVersion":"v1","kind":"Binding","metadata":{"name":"c4-plain"},"target":{"apiVersion":"v1","kind":"Node","name":"none-such"}}' |
    "${kc[@]}" create --raw "/api/v1/namespaces/default/pods/c4-plain/binding?dryRun=All" -f -
}
expect "$binding" binding "binding a pod by hand" binder

# The gateway's namespace: only its StatefulSet and check Jobs make pods.
expect deny namespace "a bare pod" try_pod c4-j "$ns" ''
live=$("${kc[@]}" -n "$ns" get pod "$gateway" -o json)
shaped() { # kind: gateway or check
  python3 -I -c '
import json, sys
kind, fullname, live = sys.argv[1], sys.argv[2], json.loads(sys.stdin.read())
image = live["spec"]["containers"][0]["image"]
spec = {"securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "c", "image": image, "securityContext": {"allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]}}}]}
if kind == "gateway":
    spec["serviceAccountName"] = fullname
    owner = {"apiVersion": "apps/v1", "kind": "StatefulSet", "name": fullname, "uid": "00000000-0000-0000-0000-000000000000"}
    name = fullname + "-c4"
else:
    spec["serviceAccountName"] = fullname + "-check"
    spec["containers"][0]["command"] = ["/meshgw", "check"]
    owner = {"apiVersion": "batch/v1", "kind": "Job", "name": fullname + "-check", "uid": "00000000-0000-0000-0000-000000000000"}
    name = fullname + "-check-c4"
print(json.dumps({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "ownerReferences": [owner]}, "spec": spec}))
' "$1" "$fullname" <<<"$live"
}
make_as() { # kind, user (empty: the caller's own)
  local as=()
  [[ -n $2 ]] && as=(--as="$2")
  shaped "$1" | "${kc[@]}" -n "$ns" create --dry-run=server ${as[@]+"${as[@]}"} -f -
}
# within5 runs a command that blocks when allowed, for 5 s at most.
within5() {
  "$@" & local pid=$!
  (sleep 5; kill "$pid") >/dev/null 2>&1 & local timer=$!
  wait "$pid"; local code=$?
  kill "$timer" 2>/dev/null
  return $code
}
expect allow namespace "a gateway pod from the StatefulSet controller" make_as gateway system:serviceaccount:kube-system:statefulset-controller
expect allow namespace "a check pod from the job controller" make_as check system:serviceaccount:kube-system:job-controller
expect deny namespace "a gateway pod from an admin" make_as gateway ""
expect deny namespace "exec into the gateway" "${kc[@]}" -n "$ns" exec "$gateway" -- /c4-none
expect deny namespace "attach to the gateway" within5 "${kc[@]}" -n "$ns" attach "$gateway"
expect deny namespace "port-forward to the gateway" within5 "${kc[@]}" -n "$ns" port-forward "pod/$gateway" :9090
ephemeral() {
  python3 -I -c '
import json, sys
pod = json.loads(sys.stdin.read())
pod["metadata"].pop("resourceVersion", None)  # an update without a precondition
pod["spec"].setdefault("ephemeralContainers", []).append({"name": "c4", "image": "registry.k8s.io/pause:3.10",
    "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}})
print(json.dumps(pod))' <<<"$live" |
    "${kc[@]}" replace --raw "/api/v1/namespaces/$ns/pods/$gateway/ephemeralcontainers?dryRun=All" -f -
}
expect deny namespace "an ephemeral container" ephemeral
expect deny namespace "changing the gateway's image" "${kc[@]}" -n "$ns" set image "pod/$gateway" meshgw=registry.k8s.io/pause:3.10 --dry-run=server
expect allow namespace "labelling the gateway's pod" "${kc[@]}" -n "$ns" label "pod/$gateway" c4-case=1 --dry-run=server
expect allow namespace "the gateway's logs" "${kc[@]}" -n "$ns" logs "$gateway" --tail=1

# Tokens: nobody but the gateway mints its groups'.
expect deny token-others "minting $group by hand" "${kc[@]}" -n "$ns" create token "$group" --duration=10m

if [[ ${DISRUPTIVE:-} == 1 ]]; then
  # Never the last ready replica.
  ready=$("${kc[@]}" -n "$ns" get statefulset "$fullname" -o jsonpath='{.status.readyReplicas}')
  if (( ${ready:-0} < 2 )); then
    echo "FAIL  DISRUPTIVE needs two ready replicas, has ${ready:-0}"
    exit 1
  fi
  old=$("${kc[@]}" -n "$ns" get pod "$fullname-1" -o jsonpath='{.metadata.uid}')
  "${kc[@]}" -n "$ns" delete pod "$fullname-1" --wait=true >/dev/null
  for _ in $(seq 60); do
    new=$("${kc[@]}" -n "$ns" get pod "$fullname-1" -o jsonpath='{.metadata.uid}' 2>/dev/null)
    [[ -n $new && $new != "$old" ]] && break
    sleep 3
  done
  if "${kc[@]}" -n "$ns" wait --for=condition=Ready "pod/$fullname-1" --timeout=180s >/dev/null 2>&1; then
    echo "ok    replica 1 recreated and ready"
  else
    echo "FAIL  replica 1 not recreated and ready"; failed=1
  fi
fi
exit $failed
