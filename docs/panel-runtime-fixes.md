# Panel runtime compatibility fixes

## Scope and classification

Panel `route`, `route_ip` and `default_out` are trusted administrator configuration,
not subscriber input. Their interaction with a local private-outbound switch is a
P2 configuration-precedence issue, not evidence of subscriber privilege escalation.
The local switch still takes precedence when disabled. When enabled, panel freedom
outbounds receive an explicit private allow fallback; explicit panel final rules
retain their precedence over that fallback.

## Implemented

- Prepare users in both replacement and rollback handlers before hot swapping.
  Remove Xray's partially registered failed handler before restoring the old one.
- Retain the desired node snapshot until successful application. A subsequent
  ETag/304 response no longer prevents retry after local bind/start failure.
- Reconcile user additions against the actual handler even when the panel returns
  a cached list, rather than assuming the last fetched list was fully applied.
- Drain old-tag/UUID counters into pending traffic, retain them for late writes
  from in-flight connections, and serialize counter collection with lifecycle
  changes and other reports. Report acknowledgement subtracts only sent bytes.
- Send `{}` to `/push` during idle cycles through a validated panel-client wrapper
  (UniProxy 0.1.1 skips empty traffic). Cap the reporting interval at 120 seconds
  because panel node health becomes stale after 300 seconds. No heartbeat retries
  or redirects that could duplicate accounting or expose credentials.
- Use `device_limit` for atomic, per-node unique-source-IP admission. Multiple
  connections from the same IP share a slot. Refresh global usage via `alivelist`
  and retain the last snapshot if the API fails.
- Re-read speed limits during bounded, cancellable transfer reservations. Existing
  connections observe limited/unlimited changes. Disable raw socket splicing for
  managed users so it cannot bypass custom accounting or dynamic throttling.

## Validation

Local full race suite, vet and build include tests for:

- A real Xray listener with an occupied replacement port: two failed attempts,
  restored user count, real user/config ETag/304 responses, then successful retry
  after freeing the port without changing the panel response.
- Initial old-tag traffic plus late increments through retained counter pointers:
  exact upload/download sums reported once, followed by two empty idle pushes.
- Panel `alivelist` consumption; same-IP sharing, cross-IP rejection, release and
  concurrent local admission.
- Existing blocked transfers observing speed changes and cancellation.
- Custom freedom allow fallback preserving explicit administrator rules.
- Empty push redirect refusal and token-safe errors.

The lifecycle/traffic/idle regression binary also passed on the Linux VPS.
An additional run against the isolated Laravel development panel used dedicated
hidden nodes and users plus the temporary UniProxy entrypoint described in
`xray-26.9.9-validation.md`. Production node and panel were untouched.

Observed remotely:

- Idle `LAST_PUSH_AT` advanced between two observations with no proxy traffic.
- `device_limit=1`: a second Docker source IP was denied, while another connection
  from the admitted source IP received data.
- One persistent download connection changed from unlimited (761,856 bytes / 2s)
  to 1 Mbps (393,216 bytes / 3s), then back to unlimited (1,212,416 bytes / 2s),
  without reconnecting.
- Test containers, panel records, credentials, temporary binaries and listeners
  were cleaned up. Production `stao-us` and its 443 listener remained unchanged.

## Follow-up lifecycle hardening

- Timestamp successful local alive reports and expire subtraction credits after
  90 seconds (conservative relative to the reference panel's 100-second per-node
  expiry). Serialize heartbeat and count refresh to avoid overlapping snapshots.
- Replace stop-on-error periodic callbacks with owned workers that keep retrying
  errors. Stop prevents new work; shutdown joins in-flight callbacks before core
  teardown. If workers exceed the 10-second shutdown deadline, the core is left
  intact rather than destroyed concurrently.
- Shutdown removes the inbound listener and performs a full-user, old-counter
  traffic drain using a fresh deadline-bound context, not the cancelled polling
  context. Repeated Close calls do not duplicate the final report. Failed reports
  return an error and keep pending counters in memory.
- Docker dependency download is cached separately from source; `.dockerignore`
  excludes Git metadata and common local secrets/artifacts. Runtime Alpine is
  pinned to the 3.23 release line (not an immutable digest).

Added tests cover expired local credits with remote occupancy, retry after a
callback error, waiting for an active callback, cancellation of an in-flight
report followed by final drain, report failure retaining pending bytes, and a
shutdown batch exceeding 2048 users. They passed under the local race detector
and as a Linux test binary on the VPS. This follow-up used an isolated simulated
API, not another full Laravel end-to-end run.

## Boundaries and tradeoffs

- Final shutdown reporting is best-effort, not durable exactly-once accounting.
  Forced termination, a failed final API call, or data still in flight after the
  listener closes can leave unreported bytes. A durable outbox and end-to-end
  idempotency require separate design and panel cooperation. Cancelling a report
  after the panel accepted it but before acknowledgement also creates ambiguity.

- Global device counts are eventually consistent: `alive` and `alivelist` provide
  no distributed atomic reservation, and panel cache can lag. This is not a hard
  simultaneous cross-node device cap. Counts use IPs, not hardware identities.
  Existing connections are not forcibly disconnected when a limit decreases.
- Retired counters are kept until core shutdown to avoid losing late traffic.
  Frequent port/UUID churn increases retained metadata; safe garbage collection
  needs explicit connection-lifetime tracking and is deferred.
- The temporary Laravel test entrypoint runs traffic jobs synchronously. Normal
  production queue workers and long-term load were not tested in this run.
- Dynamic limiting trades raw-splice throughput for consistent policy and stats.
  Performance benchmarking under production concurrency remains follow-up work.
