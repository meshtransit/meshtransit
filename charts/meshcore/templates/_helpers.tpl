{{- define "meshcore.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "meshcore.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "meshcore.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "meshcore.roleFullname" -}}
{{- printf "%s-%s" (include "meshcore.fullname" .root) .role | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "meshcore.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
app.kubernetes.io/name: {{ include "meshcore.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: meshtransit
{{- end -}}

{{- define "meshcore.selectorLabels" -}}
app.kubernetes.io/name: {{ include "meshcore.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "meshcore.roleSelectorLabels" -}}
{{ include "meshcore.selectorLabels" .root }}
app.kubernetes.io/component: {{ .role }}
{{- end -}}

{{- define "meshcore.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}
{{- end -}}

{{- define "meshcore.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "meshcore.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "meshcore.runtimeEnv" -}}
{{- $root := .root -}}
{{- $role := .role -}}
{{- $storage := or (eq $role "all") (eq $role "api") (eq $role "control") (eq $role "worker") -}}
{{- $runtime := or (eq $role "all") (eq $role "api") (eq $role "control") -}}
{{- $worker := or (eq $role "all") (eq $role "worker") -}}
{{- $control := or (eq $role "all") (eq $role "control") -}}
- name: MESHTRANSIT_ROLE
  value: {{ $role | quote }}
- name: MESHTRANSIT_HEALTH_ADDRESS
  value: "0.0.0.0:8081"
- name: MESHTRANSIT_LOG_LEVEL
  value: {{ $root.Values.config.logLevel | quote }}
- name: MESHTRANSIT_SHUTDOWN_TIMEOUT
  value: {{ $root.Values.config.shutdownTimeout | quote }}
- name: MESHTRANSIT_DEPENDENCY_CHECK_TIMEOUT
  value: {{ $root.Values.config.dependencyCheckTimeout | quote }}
- name: MESHTRANSIT_DEPENDENCY_CHECK_INTERVAL
  value: {{ $root.Values.config.dependencyCheckInterval | quote }}
{{- if $storage }}
- name: MESHTRANSIT_POSTGRES_ADDRESS
  value: {{ $root.Values.config.postgres.address | quote }}
- name: MESHTRANSIT_POSTGRES_DATABASE
  value: {{ $root.Values.config.postgres.database | quote }}
- name: MESHTRANSIT_POSTGRES_CA_FILE
  value: /run/secrets/meshcore/postgres-ca.pem
- name: MESHTRANSIT_REDIS_ADDRESS
  value: {{ $root.Values.config.redis.address | quote }}
- name: MESHTRANSIT_REDIS_USERNAME
  value: {{ $root.Values.config.redis.username | quote }}
- name: MESHTRANSIT_REDIS_PASSWORD_FILE
  value: /run/secrets/meshcore/redis-password
- name: MESHTRANSIT_REDIS_CA_FILE
  value: /run/secrets/meshcore/redis-ca.pem
- name: MESHTRANSIT_REDIS_POOL_SIZE
  value: {{ $root.Values.config.redis.poolSize | quote }}
{{- end }}
{{- if $runtime }}
- name: MESHTRANSIT_POSTGRES_RUNTIME_USER
  value: {{ $root.Values.config.postgres.runtimeUser | quote }}
- name: MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE
  value: /run/secrets/meshcore/postgres-runtime-password
- name: MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS
  value: {{ $root.Values.config.postgres.runtimeMaxConnections | quote }}
{{- end }}
{{- if $worker }}
- name: MESHTRANSIT_POSTGRES_WORKER_USER
  value: {{ $root.Values.config.postgres.workerUser | quote }}
- name: MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE
  value: /run/secrets/meshcore/postgres-worker-password
- name: MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS
  value: {{ $root.Values.config.postgres.workerMaxConnections | quote }}
- name: MESHTRANSIT_NETWORK_REVISION_BATCH_SIZE
  value: {{ $root.Values.config.worker.batchSize | quote }}
- name: MESHTRANSIT_NETWORK_REVISION_LEASE
  value: {{ $root.Values.config.worker.lease | quote }}
- name: MESHTRANSIT_NETWORK_REVISION_POLL_INTERVAL
  value: {{ $root.Values.config.worker.pollInterval | quote }}
- name: MESHTRANSIT_NETWORK_REVISION_RETRY_DELAY
  value: {{ $root.Values.config.worker.retryDelay | quote }}
- name: MESHTRANSIT_NETWORK_REVISION_OPERATION_TIMEOUT
  value: {{ $root.Values.config.worker.operationTimeout | quote }}
{{- end }}
{{- if $control }}
- name: MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID
  value: {{ $root.Values.config.enrollment.activeKeyID | quote }}
- name: MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_FILE
  value: /run/secrets/meshcore/enrollment-digest-active-key
{{- if $root.Values.config.enrollment.previousKeyID }}
- name: MESHTRANSIT_ENROLLMENT_DIGEST_PREVIOUS_KEY_ID
  value: {{ $root.Values.config.enrollment.previousKeyID | quote }}
- name: MESHTRANSIT_ENROLLMENT_DIGEST_PREVIOUS_KEY_FILE
  value: /run/secrets/meshcore/enrollment-digest-previous-key
{{- end }}
- name: MESHTRANSIT_CONTROL_ADDRESS
  value: "0.0.0.0:8443"
- name: MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE
  value: /run/secrets/meshcore/control-tls.crt
- name: MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE
  value: /run/secrets/meshcore/control-tls.key
- name: MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE
  value: /run/secrets/meshcore/control-noise-private-key
- name: MESHTRANSIT_CONTROL_MAX_SESSIONS
  value: {{ $root.Values.config.control.maxSessions | quote }}
- name: MESHTRANSIT_CONTROL_MAX_STREAMS_PER_SESSION
  value: {{ $root.Values.config.control.maxStreamsPerSession | quote }}
- name: MESHTRANSIT_CONTROL_HANDSHAKE_TIMEOUT
  value: {{ $root.Values.config.control.handshakeTimeout | quote }}
- name: MESHTRANSIT_CONTROL_READ_IDLE_TIMEOUT
  value: {{ $root.Values.config.control.readIdleTimeout | quote }}
- name: MESHTRANSIT_CONTROL_PING_TIMEOUT
  value: {{ $root.Values.config.control.pingTimeout | quote }}
- name: MESHTRANSIT_CONTROL_WRITE_TIMEOUT
  value: {{ $root.Values.config.control.writeTimeout | quote }}
- name: MESHTRANSIT_CONTROL_MAP_REQUEST_TIMEOUT
  value: {{ $root.Values.config.control.mapRequestTimeout | quote }}
- name: MESHTRANSIT_CONTROL_MAP_STATEMENT_TIMEOUT
  value: {{ $root.Values.config.control.mapStatementTimeout | quote }}
- name: MESHTRANSIT_CONTROL_MAP_TRANSACTION_IDLE_LIMIT
  value: {{ $root.Values.config.control.mapTransactionIdleLimit | quote }}
- name: MESHTRANSIT_CONTROL_MAP_PRESENCE_TTL
  value: {{ $root.Values.config.control.mapPresenceTTL | quote }}
- name: MESHTRANSIT_CONTROL_MAP_COORDINATION_TIMEOUT
  value: {{ $root.Values.config.control.mapCoordinationTimeout | quote }}
- name: MESHTRANSIT_CONTROL_MAP_KEEPALIVE_INTERVAL
  value: {{ $root.Values.config.control.mapKeepaliveInterval | quote }}
- name: MESHTRANSIT_CONTROL_MAP_RECONCILE_INTERVAL
  value: {{ $root.Values.config.control.mapReconcileInterval | quote }}
- name: MESHTRANSIT_REGISTRATION_MAX_ATTEMPTS
  value: {{ $root.Values.config.registration.maxAttempts | quote }}
- name: MESHTRANSIT_REGISTRATION_ROLLBACK_TIMEOUT
  value: {{ $root.Values.config.registration.rollbackTimeout | quote }}
- name: MESHTRANSIT_REGISTRATION_PENDING_TTL
  value: {{ $root.Values.config.registration.pendingTTL | quote }}
- name: MESHTRANSIT_REGISTRATION_ADDRESS_CANDIDATE_LIMIT
  value: {{ $root.Values.config.registration.addressCandidateLimit | quote }}
- name: MESHTRANSIT_REGISTRATION_STATEMENT_TIMEOUT
  value: {{ $root.Values.config.registration.statementTimeout | quote }}
- name: MESHTRANSIT_REGISTRATION_LOCK_TIMEOUT
  value: {{ $root.Values.config.registration.lockTimeout | quote }}
- name: MESHTRANSIT_REGISTRATION_IDLE_TIMEOUT
  value: {{ $root.Values.config.registration.idleTimeout | quote }}
- name: MESHTRANSIT_REGISTRATION_RETRY_INITIAL
  value: {{ $root.Values.config.registration.retryInitial | quote }}
- name: MESHTRANSIT_REGISTRATION_RETRY_MAXIMUM
  value: {{ $root.Values.config.registration.retryMaximum | quote }}
{{- end }}
{{- end -}}

{{- define "meshcore.runtimeVolumes" -}}
{{- $root := .root -}}
{{- $role := .role -}}
{{- $storage := or (eq $role "all") (eq $role "api") (eq $role "control") (eq $role "worker") -}}
{{- $runtime := or (eq $role "all") (eq $role "api") (eq $role "control") -}}
{{- $worker := or (eq $role "all") (eq $role "worker") -}}
{{- $control := or (eq $role "all") (eq $role "control") -}}
{{- if $storage }}
- name: runtime-files
  projected:
    defaultMode: 0440
    sources:
      - configMap:
          name: {{ $root.Values.config.postgres.caConfigMap }}
          items:
            - key: {{ $root.Values.config.postgres.caKey }}
              path: postgres-ca.pem
      - configMap:
          name: {{ $root.Values.config.redis.caConfigMap }}
          items:
            - key: {{ $root.Values.config.redis.caKey }}
              path: redis-ca.pem
      - secret:
          name: {{ $root.Values.runtimeSecret.name }}
          items:
            - key: {{ $root.Values.runtimeSecret.keys.redisPassword }}
              path: redis-password
{{- if $runtime }}
            - key: {{ $root.Values.runtimeSecret.keys.postgresRuntimePassword }}
              path: postgres-runtime-password
{{- end }}
{{- if $worker }}
            - key: {{ $root.Values.runtimeSecret.keys.postgresWorkerPassword }}
              path: postgres-worker-password
{{- end }}
{{- if $control }}
            - key: {{ $root.Values.runtimeSecret.keys.enrollmentDigestActiveKey }}
              path: enrollment-digest-active-key
{{- if $root.Values.config.enrollment.previousKeyID }}
            - key: {{ $root.Values.runtimeSecret.keys.enrollmentDigestPreviousKey }}
              path: enrollment-digest-previous-key
{{- end }}
            - key: {{ $root.Values.runtimeSecret.keys.controlNoisePrivateKey }}
              path: control-noise-private-key
      - secret:
          name: {{ $root.Values.controlTLS.secretName }}
          items:
            - key: {{ $root.Values.controlTLS.certificateKey }}
              path: control-tls.crt
            - key: {{ $root.Values.controlTLS.privateKeyKey }}
              path: control-tls.key
{{- end }}
{{- end }}
{{- end -}}
