# Console read planning — 2026-10-02

## Change and authority contract

Console account-session resolution, scope projection, deployment capabilities,
Device inventory and active-policy reads select PostgreSQL generic plans inside
their bounded transaction. The setting is transaction-local and is appended to
the existing timeout setup, without an additional database round trip. Mutation
transactions retain their existing planner settings.

This reuses parameterized query plans, not query results. Every read still
executes current session, generation, membership, permission, scope and expiry
checks in PostgreSQL. Repeatable-read boundaries, authority locks, row limits,
pagination and response whitelists remain in place. Redis remains an accelerator
for rate limits, presence and revision notifications; it is not an authority or
policy-result cache.

Active-policy reads now expose the bounded `active_policy_read` PostgreSQL
operation metric. Labels contain no Account, Workspace, Network or Device IDs.

## Engineering measurements

The diagnosed workload had seven test Devices and a small active policy. One
isolated HTTP Device read took 246.95 ms inside Core: session resolution took
55.96 ms and inventory loading took 184.53 ms, with no pool wait in that request.
Redis rate-limit commands averaged 2.74 ms in the observed window. These samples
identified the database path as the first optimization target.

The SQL experiment used PostgreSQL 18.6 on Linux, default JIT settings and ten
fresh physical connections per planner mode, run sequentially. Each connection
executed each of the three read functions three times in a transaction that was
rolled back. Only the second call was retained as one sample per operation.
This separates cold planning from reuse and avoids PostgreSQL's later automatic
custom-to-generic transition. Setting JIT off did not improve this workload.

`benchstat` was pinned to `golang.org/x/perf` commit `406019bb8b68`, using Go
1.26.8. Its comparison was:

```text
                              auto             generic          vs base
ConsoleReadSecondCall/devices 195.820m ± 16%     1.310m ± 3%       -99.33% (p=0.000 n=10)
ConsoleReadSecondCall/policy  181.365m ± 22%     1.140m ± 4%       -99.37% (p=0.000 n=10)
ConsoleReadSecondCall/scopes  202.215m ± 13%     1.005m ± 6%       -99.50% (p=0.000 n=10)
geomean                       192.9m            1.145m           -99.41%
```

Here `m` means milliseconds. These are server-side SQL function durations, not
end-to-end HTTP latency. Cold generic-plan creation remained approximately
190–215 ms for Device/scope reads. PostgreSQL's automatic mode can eventually
reuse generic plans too; the improvement specifically avoids repeated custom
planning on newly used pool connections. No Go allocation optimization was made;
SQL timings provide no Go allocation result.

## Correctness and limits

The complete Core quality gate passed, including shuffled race tests, lint and
reachable-vulnerability checks. The disposable PostgreSQL migration and
functional suite passed in 21.046 seconds. A repeated generic-plan integration
read still enforces pagination, response whitelists and exact Network scope.
Revoking `device.read` and `policy.read` denies the next read after plan reuse.

This is a bounded POC engineering measurement. Database CPU/RAM and a large,
skewed multi-Workspace workload were not recorded or qualified. Generic plans
can be less selective for skewed data; test that workload before extending this
setting to other paths. No fleet-scale throughput, HTTP p95 or convergence SLA
is established by these SQL results. Live HTTP verification belongs in the
separate rollout record.
