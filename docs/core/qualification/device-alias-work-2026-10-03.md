# Bounded Device alias work qualification

Schema87 introduces an isolated worker-only work-hint reader and endpoint-level
Resource quarantine without a consumer selector. Released schemas85–86 are
unchanged. Runtime receives no new function or table privileges.

Discovery materializes at most128 endpoint IDs before changing exact endpoint
RLS selectors, then visits at most128 consumer/action rows per page. A public
keyset cursor advances across no-action rows and completed endpoints. An endpoint
scan budget also bounds empty endpoints. No candidate is authority: a separate
short guarded transaction rechecks admission/evidence for each action.

Terminal Resource cleanup precedes consumer cleanup. It does not depend on a
consumer Device remaining in the work set. Active target/import, lifecycle,
recovery, Network generation, consent/export and current lease/key pins determine
terminal work. Policy denial or temporary absence of a client claim prevents
publication without terminally retiring a valid slot. The map reader enforces
all current packet predicates independently of worker scheduling.

The process worker owns one sequential goroutine and finite per-operation
contexts. Failed/uncertain candidates still advance the cursor; the next sweep
rediscovers PostgreSQL state. No read transaction survives discovery, no network
I/O runs under write locks, and shutdown cancellation joins blocked work. Logs
use fixed error codes; measurements contain no tenant/device identifiers.

Verification: PostgreSQL18.6/Redis8.8 migrations1–87 uncached race passed in
33.662s. Actual mesh_worker tests paginate to EOF with size1, restore poisoned
selectors and make no discovery authority mutation. Missing rule/claim suppress
publication hints. Changed consent, target removal and import version produce
terminal cleanup. Orphan Resource aliases with no consumer are quarantined with
complete bilateral evidence. Foreign Deployment, runtime role and oversize page
are denied. Adapter/worker races cover cleanup, strict shape, failed reads,
stalled/duplicate/foreign hints, no-action progress, failed candidate fairness,
shutdown/blocked read join, typed nil and bounded configuration. Full make quality
passed before the final endpoint cleanup amendment; changed-package race and
integration lint qualify that amendment. Staged secrets are scanned before push.

Runtime configuration/composition is the next checkpoint. This worker is not
enabled in the live POC. Genuine Core/SSO/client sharing and DNS qualification
remain required; the earlier encrypted fixture PASS is separate evidence.
