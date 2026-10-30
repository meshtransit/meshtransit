{{/* Names. fullname is at most 52 characters (StatefulSet revision labels). */}}
{{- define "kg.name" -}}
{{- default "meshgw" .Values.nameOverride | trunc 52 | trimSuffix "-" -}}
{{- end -}}

{{- define "kg.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride -}}
{{- else -}}
{{- include "kg.name" . -}}
{{- end -}}
{{- end -}}

{{- define "kg.checkName" -}}{{ include "kg.fullname" . }}-check{{- end -}}
{{- define "kg.statePrefix" -}}{{ include "kg.fullname" . }}-state{{- end -}}
{{- define "kg.serviceAccountUser" -}}system:serviceaccount:{{ .Release.Namespace }}:{{ include "kg.fullname" . }}{{- end -}}

{{/* Cluster-scoped objects have fixed names: one install per cluster (Q89). */}}
{{- define "kg.clusterName" -}}meshtransit-kube-gateway{{- end -}}

{{- define "kg.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kg.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The gateway's pods only: the check's pods share the release labels
     (review c3 H1). */}}
{{- define "kg.gatewaySelector" -}}
{{ include "kg.selectorLabels" . }}
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "kg.labels" -}}
{{ include "kg.selectorLabels" . }}
app.kubernetes.io/part-of: meshtransit-kube-gateway
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{/* The pinned image: repository@digest, or repository:tag for labs. */}}
{{- define "kg.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}
{{- end -}}

{{/* The groups' ServiceAccounts, as a JSON list of strings. */}}
{{- define "kg.groupAccounts" -}}
{{- $accounts := list -}}
{{- range .Values.groups -}}{{- $accounts = append $accounts (printf "mt-%s" .name) -}}{{- end -}}
{{- toJson $accounts -}}
{{- end -}}

{{/* Namespaces exempt from placement: the gateway's and the node-level ones. */}}
{{- define "kg.placementExempt" -}}
{{- toJson (uniq (prepend .Values.nodeLevelNamespaces .Release.Namespace)) -}}
{{- end -}}

{{/* MESHGW_GUARDED_NAMESPACES: node-level namespaces but kube-system (Q76). */}}
{{- define "kg.guarded" -}}
{{- without .Values.nodeLevelNamespaces "kube-system" | join "," -}}
{{- end -}}

{{/* MESHGW_KUBE_GROUPS, from the groups' values. */}}
{{- define "kg.kubeGroups" -}}
{{- $groups := list -}}
{{- range .Values.groups -}}
{{- $group := dict "name" .name -}}
{{- if .default -}}{{- $_ := set $group "default" true -}}{{- end -}}
{{- if .namespaces -}}{{- $_ := set $group "namespaces" .namespaces -}}{{- end -}}
{{- if .privileged -}}{{- $_ := set $group "privileged" true -}}{{- end -}}
{{- if .allowedPrincipals -}}{{- $_ := set $group "allowedPrincipals" .allowedPrincipals -}}{{- end -}}
{{- if .allowImpersonation -}}{{- $_ := set $group "allowImpersonation" true -}}{{- end -}}
{{- $groups = append $groups $group -}}
{{- end -}}
{{- toJson $groups -}}
{{- end -}}

{{/* Whether the preflight hook runs. */}}
{{- define "kg.preflight" -}}
{{- if and (or .Values.placement.enforce .Values.binding.enforce) (not .Values.preflight.skip) -}}true{{- end -}}
{{- end -}}

{{/* A CEL list literal of strings. */}}
{{- define "kg.celList" -}}
[{{- range $index, $item := . -}}{{- if $index }}, {{ end -}}'{{ $item }}'{{- end -}}]
{{- end -}}

{{/* A pod (object or oldObject) targeting the gateway pool (Q97): its taint's key, or the pool label in a
     selector that chooses it (an affinity avoiding the pool, NotIn or DoesNotExist, does not; review c4). */}}
{{- define "kg.targetsPool" -}}
(has({{ . }}.spec.tolerations) && {{ . }}.spec.tolerations.exists(t, has(t.key) && t.key == 'meshtransit.net/gateway')) ||
(has({{ . }}.spec.nodeSelector) && 'node-restriction.kubernetes.io/meshtransit-gateway-pool' in {{ . }}.spec.nodeSelector) ||
(has({{ . }}.spec.affinity) && has({{ . }}.spec.affinity.nodeAffinity) &&
 ((has({{ . }}.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution) &&
   has({{ . }}.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms) &&
   {{ . }}.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms.exists(term,
     has(term.matchExpressions) &&
     term.matchExpressions.exists(e, e.key == 'node-restriction.kubernetes.io/meshtransit-gateway-pool' && e.operator in ['In', 'Exists', 'Gt', 'Lt']))) ||
  (has({{ . }}.spec.affinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution) &&
   {{ . }}.spec.affinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution.exists(p,
     has(p.preference) && has(p.preference.matchExpressions) &&
     p.preference.matchExpressions.exists(e, e.key == 'node-restriction.kubernetes.io/meshtransit-gateway-pool' && e.operator in ['In', 'Exists', 'Gt', 'Lt'])))))
{{- end -}}

{{/* A pod tolerating every taint. */}}
{{- define "kg.toleratesAll" -}}
has({{ . }}.spec.tolerations) && {{ . }}.spec.tolerations.exists(t,
  (!has(t.key) || t.key == '') && has(t.operator) && t.operator == 'Exists')
{{- end -}}

{{/* Hook metadata of the check's objects (Q95, Q102). */}}
{{- define "kg.hookMeta" -}}
annotations:
  helm.sh/hook: {{ .events }}
  helm.sh/hook-weight: "-10"
  helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded,hook-failed
{{- end -}}

{{/* The fingerprints of the admission objects the chart renders, by name:
     the same fields and JSON as meshgw check reads live (kubecheck
     policyHash, bindingHash; review c2b H4). The chart writes no default the
     API server adds (matchPolicy, empty selectors, a rule's scope), so what
     it renders is already normalized. */}}
{{- define "kg.policyHashes" -}}
{{- $hashes := dict -}}
{{- range $file := list "policies-token.yaml" "policies-placement.yaml" "policies-namespace.yaml" -}}
{{- range $doc := splitList "\n---\n" (include (print $.Template.BasePath "/" $file) $) -}}
{{- $object := fromYaml $doc -}}
{{- if eq (toString (get $object "kind")) "ValidatingAdmissionPolicy" -}}
{{- $fields := dict "validations" (dig "spec" "validations" nil $object) "matchConditions" (dig "spec" "matchConditions" nil $object)
    "variables" (dig "spec" "variables" nil $object) "auditAnnotations" (dig "spec" "auditAnnotations" nil $object)
    "matchConstraints" (dig "spec" "matchConstraints" nil $object) -}}
{{- $_ := set $hashes (dig "metadata" "name" "" $object) (toJson $fields | sha256sum) -}}
{{- else if eq (toString (get $object "kind")) "ValidatingAdmissionPolicyBinding" -}}
{{- $fields := dict "policyName" (dig "spec" "policyName" nil $object) "validationActions" (dig "spec" "validationActions" nil $object)
    "paramRef" (dig "spec" "paramRef" nil $object) "matchResources" (dig "spec" "matchResources" nil $object) -}}
{{- $_ := set $hashes (printf "binding/%s" (dig "metadata" "name" "" $object)) (toJson $fields | sha256sum) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- toJson $hashes -}}
{{- end -}}

{{/* The gateway's environment: the ConfigMap's data, and the checksum that
     rolls the replicas only when it changes (review c3 L2). */}}
{{- define "kg.configData" -}}
MESHGW_CONTROL_URL: {{ .Values.control.url | quote }}
MESHGW_CONTROL_FINGERPRINT: {{ .Values.control.fingerprint | quote }}
MESHGW_CLUSTER: {{ .Values.cluster | quote }}
MESHGW_JOIN_DIR: /etc/meshgw/join
MESHGW_ENVELOPE_DIR: /etc/meshgw/envelope
MESHGW_STATE_SECRET_PREFIX: {{ include "kg.statePrefix" . | quote }}
MESHGW_SERVICE_ACCOUNT: {{ include "kg.fullname" . | quote }}
MESHGW_ENVELOPE_SECRET: {{ .Values.envelope.existingSecret | quote }}
MESHGW_JOIN_SECRET: {{ .Values.join.existingSecret | quote }}
MESHGW_REPLICAS: {{ int .Values.replicas | quote }}
MESHGW_KUBE_GROUPS: {{ include "kg.kubeGroups" . | quote }}
MESHGW_GUARDED_NAMESPACES: {{ include "kg.guarded" . | quote }}
MESHGW_SECRET_RESOURCES: {{ join "," .Values.secretResources | quote }}
MESHGW_KUBE_STALE_AFTER: {{ printf "%ds" (int .Values.staleAfterSeconds) | quote }}
MESHGW_API_AUDIENCES: {{ join "," .Values.apiServerAudiences | quote }}
MESHGW_KUBE_PROFILES: {{ (.Values.profiles).enabled | default false | toString | quote }}
MESHGW_TCP_SEND_BUFFER: {{ int .Values.network.tcpSendBufferBytes | quote }}
MESHGW_TCP_RECEIVE_BUFFER: {{ int .Values.network.tcpReceiveBufferBytes | quote }}
MESHGW_CERTIFICATE_DIR: /var/run/meshgw/certificate
{{- end -}}

{{/* The image pull Secrets pods in the namespace may name, as a CEL list. */}}
{{- define "kg.pullSecrets" -}}
{{- $names := list -}}
{{- range .Values.imagePullSecrets -}}{{- $names = append $names .name -}}{{- end -}}
{{- include "kg.celList" $names -}}
{{- end -}}
