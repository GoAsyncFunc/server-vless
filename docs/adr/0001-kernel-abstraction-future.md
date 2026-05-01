# ADR 0001: Kernel Abstraction Layer (Future Work)

- Status: **Proposed / Deferred**
- Date: 2026-05-01
- Decision owner: server-vless maintainers

## Context

`server-vless` currently embeds Xray-core directly: `core.Instance`, `inbound.Manager`, `stats.Manager`, `proxy.UserManager`, and the entire `infra/conf` builder family are referenced from production code in:

- `internal/app/server/server.go` — DNS / routing / policy config built via `conf.*`
- `internal/pkg/service/{builder,inboundbuilder,outboundbuilder,userbuilder}.go` — produces Xray protobuf and drives Xray feature managers
- `internal/pkg/dispatcher/default.go` — implements Xray's `routing.Dispatcher` interface to add per-user accounting
- `cmd/server/main.go` — boots `core.Instance`

This tight coupling means the project's correctness, test surface, and release cadence are bound to Xray-core's. There is recurring user interest in:

1. Switching kernels (sing-box, hysteria, custom) without rewriting the panel/integration layer.
2. Writing parts of the protocol stack natively (VLESS Vision flow, REALITY) for tighter control.
3. Keeping integration tests independent of kernel internals.

## Decision

**Defer.** Do not introduce a kernel abstraction layer in the current iteration.

Rationale:

- The ongoing work is **correctness hardening + test coverage**, not architectural reshaping. A kernel boundary that is not exercised by a second backend is speculative generality (YAGNI).
- VLESS Vision, REALITY 0-RTT, xtls, and quic-go are still in active flux upstream. Designing an abstraction against a moving target produces a leaky boundary.
- Replacing the kernel is a multi-week effort that belongs in its own RFC, not a side effect of test refactors.

Today's testability work limits itself to **package-internal interfaces** (e.g. `nodeInfoFetcher` in `internal/app/server`) that exist only to enable test seams. These are explicitly **not** the future kernel boundary.

## When to revisit

Trigger conditions for a follow-up RFC and implementation:

- A second concrete kernel (sing-box, custom) is selected with a real adoption path.
- An RFC documents the protocol-level invariants (handshake state machine, user lookup, traffic accounting, online tracking) that the abstraction must preserve.
- A migration plan exists with a behavioural test suite that proves both kernels yield identical wire output for representative panel configurations.

## Consequences

Accepted:

- We pay continued coupling to Xray-core. Upstream breaking changes propagate through `service/builder.go` and `app/server/server.go`.
- Kernel-dependent code (`Start`, `loadCore`, `reload`, `addUsers`, `reportTraffics`) remains hard to unit-test without an integration harness; coverage there will plateau without further refactoring.

Mitigated:

- A pinned `replace` directive on `xtls/xray-core` already insulates us from upstream releases between manual upgrades.
- Helper-level pure functions (DNS, route policy, user diff, scheduler bookkeeping) are now extensively tested and can survive a kernel swap unchanged.

## Out of scope for this ADR

- Choice of replacement kernel (sing-box vs custom vs Xray fork).
- Wire-protocol parity test design.
- Any production code change.

## Related

- `internal/app/server/server.go` — `nodeInfoFetcher` interface (test seam, **not** kernel boundary).
- README §"UniProxy compatibility" — describes the panel-side dependency pin policy.
