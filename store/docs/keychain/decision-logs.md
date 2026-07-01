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
  (`TestKeychainClosesEveryConnection`). The `NameHasOwner` round-trip is bounded
  by an internal 5s timeout; `New`'s signature is unchanged.
- Trade-off: a D-Bus-activatable backend that is installed but not yet running
  registers no owner, so `NameHasOwner` returns false and `New` reports
  `ErrKeychainUnavailable` even though the first real operation would have
  auto-started it. This is the deliberate price of prompt-safety and eager
  failure, and matches the two target cases (WSL/headless, no keyring daemon).
- Behavioral change: `New` now performs one D-Bus round-trip on Linux where it
  previously did no I/O, and can now fail where it previously deferred the
  failure to the first operation.

---
