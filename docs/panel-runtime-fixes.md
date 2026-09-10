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

## Boundaries and tradeoffs

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
