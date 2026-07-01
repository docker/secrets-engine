# Decision logs

This file has been added to follow technical decisions over time. Append to the
file when another important decision is taken on the `keychain` package.

---

2025-07-01 Linux Keychain

At this point in time we have decided to integrate with [keybase/go-keychain](https://github.com/keybase/go-keychain)
instead of implementing all of the `dbus` calls ourselves.

The `keybase/go-keychain` library provides:

- Secure cryptographic communication over the `dbus` connection
- Easy to use API

Some of the drawbacks are:

- Relies on a forked archived [keybase/dbus](https://github.com/keybase/dbus) library
- Low contribution activity

In future we might update the [keybase/dbus](https://github.com/keybase/dbus) with
a more up to date and maintained version, such as [godbus/dbus](https://github.com/godbus/dbus).

---

2026-06-30 Eager keychain availability probe

`New` now eagerly verifies the secret service backend is reachable before
returning, so callers learn at construction time and can
`errors.Is(err, keychain.ErrKeychainUnavailable)` to fall back, instead of
failing on the first operation. Previously the failure surfaced lazily, deep
inside the first `Get`/`Save`/`Delete`/`Filter`/`GetAllMetadata` call, which was
awkward for callers (notably in WSL and headless environments).

Decisions:

- The probe uses `org.freedesktop.DBus.NameHasOwner("org.freedesktop.secrets")`
  on the bus daemon object (`conn.BusObject()`) with `FlagNoAutoStart`, **not**
  `Collections()`/`GetProperty` on the service object. `NameHasOwner` is
  answered by `dbus-daemon` itself, so it is activation-free and prompt-free (it
  cannot reach `PromptAndWait`). `Collections()` would auto-activate the backend
  and conflate "unavailable" with "locked" / "no collection".
- One exported sentinel, `ErrKeychainUnavailable`, declared in the
  cross-platform `keychain.go` (mirroring the `ErrNoDefaultCollection`
  precedent), Linux-only behavior, a no-op on macOS/Windows. Two unexported
  causes are wrapped underneath it — `errSessionBusUnavailable` (the session bus
  could not be dialed) and `errNoSecretServiceOwner` (no backend owns the name)
  — kept unexported because no caller branches on the cause today, but wrapped
  (not discarded) so either can be promoted later with zero behavioral change.
- `ErrKeychainUnavailable` is distinct from `ErrNoDefaultCollection`: the probe
  does not assert a collection exists, so a reachable-but-uninitialized keyring
  still passes `New` and surfaces `ErrNoDefaultCollection` lazily on the first
  operation, exactly as before.
- The probe runs through the existing `newService` seam and closes its
  connection immediately, preserving the fresh-connection-per-operation contract
  (`TestKeychainClosesEveryConnection`).
- Trade-off: a D-Bus-activatable backend that is installed but not yet running
  registers no owner, so `NameHasOwner` returns false and `New` reports
  `ErrKeychainUnavailable` even though the first real operation would have
  auto-started it. This is the deliberate price of prompt-safety and eager
  failure, and matches the two target cases (WSL/headless, no keyring daemon).
- Behavioral change: `New` now performs one D-Bus round-trip on Linux where it
  previously did no I/O, and can now fail where it previously deferred the
  failure to the first operation.

---

2026-07-01 New takes a context

`New` (and the `docker-pass` `PassStore` helper that wraps it) now take a
`context.Context` as their first argument, replacing the `context.Background()`
the eager availability probe used internally.

- Rationale: the probe issues a D-Bus round-trip; the caller should own its
  cancellation and deadline rather than the library imposing a fixed internal
  timeout. The previously added internal 5s cap and the `availabilityProbeTimeout`
  constant are removed — a caller that wants a hard ceiling on `New` passes a
  context with a deadline (`context.WithTimeout`). The session bus dial inside
  `newService` remains non-ctx-aware, so `ctx` bounds the `NameHasOwner` call,
  not the dial.
- `ctx` governs construction only; `New` does not retain it for later store
  operations. On macOS/Windows the probe is a no-op and `ctx` is unused.
- This is a **breaking API change** (the earlier "signature unchanged" decision
  above is superseded). It is deliberate; the module version is bumped to
  reflect it. In-repo callers updated: `PassStore`, `store/keychain/cmd`.

---
