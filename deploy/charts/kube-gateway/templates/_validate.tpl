{{/* Rules between values the schema cannot express (design K1c §6.2). */}}
{{- define "kg.validate" -}}
{{- $v := .Values -}}
{{- if gt (len (include "kg.fullname" .)) 52 -}}{{- fail "fullname must be at most 52 characters" -}}{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$" (toString $v.cluster)) -}}
{{- fail "cluster must be a DNS label of up to 40 characters" -}}{{- end -}}
{{- if not (regexMatch "^https://[a-z0-9.-]+$" (toString $v.control.url)) -}}
{{- fail "control.url must be https://host in lower case, without a path" -}}{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" (toString $v.control.fingerprint)) -}}
{{- fail "control.fingerprint must be sha256: and 64 hex digits" -}}{{- end -}}
{{- if not $v.image.repository -}}{{- fail "image.repository is required" -}}{{- end -}}
{{- if and (not $v.image.digest) (not $v.image.allowTag) -}}
{{- fail "image.digest is required (image.allowTag is for labs only)" -}}{{- end -}}
{{- if and $v.image.digest (not (regexMatch "^sha256:[0-9a-f]{64}$" $v.image.digest)) -}}
{{- fail "image.digest must be sha256: and 64 hex digits" -}}{{- end -}}
{{- if and (not $v.image.digest) (not $v.image.tag) -}}{{- fail "image.tag is required without a digest" -}}{{- end -}}
{{- if not $v.envelope.existingSecret -}}{{- fail "envelope.existingSecret is required" -}}{{- end -}}
{{- if not $v.join.existingSecret -}}{{- fail "join.existingSecret is required" -}}{{- end -}}
{{- if not $v.apiServerAudiences -}}{{- fail "apiServerAudiences is required: helm test prints this cluster's" -}}{{- end -}}
{{- if ne (len $v.apiServerAudiences) (len (uniq $v.apiServerAudiences)) -}}{{- fail "apiServerAudiences repeats" -}}{{- end -}}
{{- range $v.apiServerAudiences -}}
{{- if or (regexMatch "[\\s,\"\\[\\]']" .) (not .) -}}{{- fail (printf "apiServerAudiences: %q is not an audience" .) -}}{{- end -}}
{{- end -}}
{{- if not (and $v.resources.limits $v.resources.limits.memory) -}}
{{- fail "resources.limits.memory is required: without it the gateway has no memory pressure signal" -}}{{- end -}}
{{- if and (not $v.allowBurstable) (ne (toString $v.resources.requests.memory) (toString $v.resources.limits.memory)) -}}
{{- fail "resources.requests.memory must equal resources.limits.memory (or set allowBurstable)" -}}{{- end -}}
{{- if not (has "kube-system" $v.nodeLevelNamespaces) -}}{{- fail "nodeLevelNamespaces must hold kube-system" -}}{{- end -}}
{{- if has .Release.Namespace $v.nodeLevelNamespaces -}}
{{- fail "nodeLevelNamespaces must not hold the gateway's namespace" -}}{{- end -}}
{{- if and $v.placement.enforce (not $v.gatewayPool.enabled) -}}
{{- fail "placement.enforce needs gatewayPool.enabled" -}}{{- end -}}
{{- if and $v.gatewayPool.enabled (not (regexMatch "^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$" (toString $v.gatewayPool.name))) -}}
{{- fail "gatewayPool.name must be a label value" -}}{{- end -}}
{{- $names := list -}}
{{- $defaults := 0 -}}
{{- $reserved := prepend $v.nodeLevelNamespaces .Release.Namespace -}}
{{- range $v.groups -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9-]{0,48}[a-z0-9])?$" (toString .name)) -}}
{{- fail (printf "group %q: the name must be a DNS label of up to 50 characters" .name) -}}{{- end -}}
{{- if has .name $names -}}{{- fail (printf "group %q is listed twice" .name) -}}{{- end -}}
{{- $names = append $names .name -}}
{{- if not .clusterRole -}}{{- fail (printf "group %q needs clusterRole" .name) -}}{{- end -}}
{{- if .default -}}{{- $defaults = add1 $defaults -}}{{- end -}}
{{- if .privileged -}}
{{- if .default -}}{{- fail (printf "group %q: the default group may not be privileged" .name) -}}{{- end -}}
{{- if not .allowedPrincipals -}}{{- fail (printf "group %q is privileged and needs allowedPrincipals" .name) -}}{{- end -}}
{{- else -}}
{{- if or .allowedPrincipals .allowImpersonation -}}
{{- fail (printf "group %q: allowedPrincipals and allowImpersonation are for privileged groups" .name) -}}{{- end -}}
{{- if or (eq .clusterRole "cluster-admin") (hasPrefix "system:" .clusterRole) -}}
{{- fail (printf "group %q: %s needs privileged: true" .name .clusterRole) -}}{{- end -}}
{{- if and (has .clusterRole (list "admin" "edit")) (not .namespaces) -}}
{{- fail (printf "group %q: %s across the cluster needs privileged, or namespaces" .name .clusterRole) -}}{{- end -}}
{{- range .namespaces -}}
{{- if has . $reserved -}}{{- fail (printf "a group that is not privileged may not hold rights in %s" .) -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if ne $defaults 1 -}}{{- fail "exactly one group must be default" -}}{{- end -}}
{{- range $v.secretResources -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$" .) -}}
{{- fail (printf "secretResources: %q is not resource.group" .) -}}{{- end -}}
{{- end -}}
{{- end -}}
