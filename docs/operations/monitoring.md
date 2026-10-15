# Monitoring

What Core and the relay expose for health, metrics and logs, and the alerts
worth setting.

## Health

Every Core process serves its operator listener
(`MESHTRANSIT_HEALTH_ADDRESS`, `127.0.0.1:8081` by default):

| Endpoint | Answers |
|---|---|
| `GET /live` | Always 200: the process runs. Use for liveness |
| `GET /ready` | 200 or 503 with the role and each dependency (`postgresql`, `redis`, `private_login`, `identity_postgresql`, `identity_configuration`, `identity_signer`) as `ready`, `unavailable` or `unknown`. Use for readiness |
| `GET /ready/login` | Readiness of the Console login; 404 when it is not configured |
| `GET /health` | Always 200, `ok` or `degraded`, with the same components |
| `GET /metrics` | Prometheus metrics |
| `GET /scale/v1/sessions` | On `control`: session counts for an autoscaler (KEDA's metrics API) |

Readiness checks every dependency every 10 seconds; PostgreSQL readiness
includes the [schema check](upgrades.md#the-rules-that-make-it-safe). In an
`all` process, losing the identity broker or the Console login lowers only
`/ready/login`; `/ready` stays up for the other work. The operator listener
belongs on a private network.

A process that cannot stop one of its components within
`MESHTRANSIT_SHUTDOWN_TIMEOUT` exits with a non-zero status and leaves its
resources to the operating system; let the orchestrator replace it.

`meshrelay` serves `/metrics` and `/healthz` (`ok N sessions`) on `--admin`
(`127.0.0.1:9479`).

## Core metrics

Names are stable; labels carry outcome names only, never identifiers.

| Area | Metrics |
|---|---|
| Process | `meshtransit_build_info{version,revision,go_version,config_schema_version}`, `meshtransit_runtime_ready`, `meshtransit_runtime_role{role}`, `meshtransit_dependency_ready{component}`, `meshtransit_login_ready` |
| MTCP | `meshtransit_mtcp_handshakes_total{result}`, `meshtransit_mtcp_sessions_active`, `meshtransit_mtcp_messages_total{direction,type}`, `meshtransit_mtcp_map_stream_ends_total{reason}`, `meshtransit_mtcp_session_limits_total{limit}`, `meshtransit_mtcp_sessions_shed_total`, `meshtransit_mtcp_unproven_sessions_closed_total`, `meshtransit_mtcp_untrusted_forwarding_total`, `meshtransit_mtcp_control_key_not_after_timestamp_seconds`, `meshtransit_mtcp_map_names_degraded_total{reason}` (`unlabeled_device`, `dropped_record`; a rising `unlabeled_device` means a write path bypassed the Device label trigger) |
| Control listener | `meshtransit_control_connections_active`, `meshtransit_control_connections_limit`, `meshtransit_control_connection_rejections_total` |
| Maps | `meshtransit_map_snapshots_total{source}`, `meshtransit_map_inventory_reads_total`, `meshtransit_map_inventory_policy_mismatches_total`, `meshtransit_map_connectivity_*` |
| Endpoints | `meshtransit_endpoint_announcements_total{outcome}` (`announced`, `deferred`, `unchanged`, `flushed`) |
| PostgreSQL | `meshtransit_postgres_operations_total{pool_role,operation,result}`, `…_operation_duration_seconds`, `meshtransit_postgres_pool_connections{pool_role,state}`, `…_pool_connections_max`, `…_pool_acquires_total{pool_role,result}` |
| Redis | `meshtransit_redis_commands_total{operation,result}`, `…_command_duration_seconds`, `meshtransit_redis_pool_connections{state}`, `…_pool_pending_requests`, `…_pool_timeouts_total`, `meshtransit_redis_subscriptions_active` |
| Wakeups | `meshtransit_revision_feed_*`, `meshtransit_connectivity_feed_*`: subscriber connected, watchers, wakeups, fan-out, reconnects |
| Revision worker | `meshtransit_revision_worker_ready_backlog_events`, `…_oldest_ready_event_age_seconds`, `…_delivery_attempts_total{result}` |
| Other workers | `meshtransit_<job>_worker_running` and `…_passes_total`, plus per-job counters, for `access_ledger`, `enforcement_ledger`, `contract_expiry`, `device_alias`, `private_endpoint` |
| Relay authority | `meshtransit_relay_authority_refreshes_total{result}`, `…_requests_total{result}`, `…_tickets_total{result}`, `…_revocations`, `…_last_refresh_timestamp_seconds` |
| API | `meshtransit_management_requests_active`, `…_limit`, `…_total{operation,result}`, `…_request_duration_seconds` |
| Sign-in | `meshtransit_browser_*`, `meshtransit_oidc_*` (login starts, callbacks, session issuance, expiry worker), `meshtransit_identity_*` (broker connections and requests) |

Go runtime and process metrics are included.

## Relay metrics

| Metric | Meaning |
|---|---|
| `meshrelay_sessions`, `meshrelay_routes` | Current sessions and routes |
| `meshrelay_handshakes_total{result}` | `ok`, `bad_ticket`, `overloaded`, `source_limited`, `replay`, … |
| `meshrelay_data_frames_total{result}` | `forwarded` and drop reasons, including `network_rate_limited` |
| `meshrelay_data_forwarded_bytes_total` | Bytes forwarded |
| `meshrelay_control_frames_total{result}`, `meshrelay_stream_events_total{result}`, `meshrelay_stun_requests_total{result}` | Control frames, TLS/WebSocket events, STUN |
| `meshrelay_sessions_closed_total{reason}` | `revoked`, `expired`, `idle`, `replaced`, … |
| `meshrelay_core_state_polls_total{result}`, `meshrelay_revocations` | Relay state from Core |
| `meshrelay_tls_certificate_expiry_timestamp_seconds` | Certificate expiry |

## Suggested alerts

| Alert | Expression (sketch) |
|---|---|
| Core not ready | `meshtransit_runtime_ready == 0` for 2 m |
| Control key expiring | `meshtransit_mtcp_control_key_not_after_timestamp_seconds - time() < 60*86400` |
| Control near capacity | `meshtransit_control_connections_active / meshtransit_control_connections_limit > 0.9`; any `meshtransit_control_connection_rejections_total` increase |
| Map streams failing | rate of `meshtransit_mtcp_map_stream_ends_total{reason="unavailable"}` > 0 |
| Policy mismatch in maps | `increase(meshtransit_map_inventory_policy_mismatches_total[15m]) > 0` |
| Untrusted proxy | sustained rate of `meshtransit_mtcp_untrusted_forwarding_total` (a proxy is missing from the trusted list) |
| Revisions not delivered | `meshtransit_revision_worker_oldest_ready_event_age_seconds > 60` |
| PostgreSQL | error rate of `meshtransit_postgres_operations_total` > 0; p99 duration > 1 s; pool acquired / max > 0.9 |
| Redis | error rate > 0; p99 > 0.5 s; `…_pool_pending_requests > 0`; timeouts |
| A worker job stopped | `meshtransit_<job>_worker_running != 1` for an enabled job |
| Enforcement mismatch | rate of `meshtransit_enforcement_ledger_worker_audited_total` > 0 (Devices not enforcing what they were sent) |
| Relay | `meshrelay_core_state_polls_total{result!="ok"}` rising; `meshrelay_tls_certificate_expiry_timestamp_seconds > 0` and within 14 days; `network_rate_limited` drops |

## Logs

Core and `meshrelay` write JSON logs to standard error
(`MESHTRANSIT_LOG_LEVEL`, `--log-level`).

- **Core** is written not to log keys, tokens, cookies, OIDC codes,
  registration links, policy contents, DNS names, endpoints or topology, and
  its logger redacts the value of every attribute whose name looks sensitive (`error`, `email`,
  `query`, anything containing `key`, `token`, `secret`, `password`, `cookie`,
  `url`, …). Because the `error` value is redacted, diagnose with the
  `error_code` attribute, which names the failure; for configuration errors it
  is `invalid_configuration`, without the variable.
- **meshrelay** does not redact attribute values: error texts and, for ACME,
  its host name appear as they are.
