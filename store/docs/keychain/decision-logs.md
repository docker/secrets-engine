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

2026-07-01 ctx-aware, no-autolaunch dial + short default probe timeout

Follow-up to the two entries above, making the probe fast and the dial honor the
context. These changes touch the shared `newService`/`kc.NewService` path, so
every store operation (not only the probe) benefits.

- **No autolaunch.** `kc.NewService` now dials with
  `dbus.SessionBusPrivateNoAutoStartup` instead of `dbus.ConnectSessionBus`.
  `ConnectSessionBus` resolves the address with `autolaunch=true`, which on a
  host with no `DBUS_SESSION_BUS_ADDRESS` (exactly the WSL/headless target case)
  execs `dbus-launch` — slow, and a side effect (it spawns a bus). The probe's
  whole point is to *detect* an absent bus, so launching one is wrong. With
  no-autostartup the missing-bus case now fails fast with `ErrNoSessionBus`.
  `NewService` performs the `Auth`+`Hello` handshake itself, which
  `ConnectSessionBus` previously did.
- **Socket pre-check.** Before dialing, `NewService` resolves the
  `unix:path=` endpoint from `DBUS_SESSION_BUS_ADDRESS` and `os.Stat`s it,
  returning `ErrNoSessionBus` immediately if it is missing (abstract/tcp
  addresses and an unset address fall through to a normal dial). This is a fast
  path with a clearer error; the unix dial would also have failed fast.
- **ctx-aware dial.** `newService` takes a `context.Context` threaded from `New`
  (probe) and from each store operation. It is passed to godbus via
  `dbus.WithContext`, so cancelling `ctx` tears the connection down and bounds
  `Auth`/`Hello`/`NameHasOwner`. The raw socket dial inside godbus is still not
  ctx-aware, but a unix dial fails immediately when the socket is missing or
  unaccepting, and the pre-dial stat covers the stale-address case.
- **Short default probe timeout, reinstated.** The internal cap removed in the
  entry above is back as `defaultProbeTimeout` (2s, down from the original 5s),
  but applied **only when the caller's `ctx` has no deadline**. A caller-supplied
  deadline always wins, so this keeps `New` responsive for callers passing
  `context.Background()` (e.g. `store/keychain/cmd`) without taking ownership of
  cancellation away from callers who want it. This supersedes the "no internal
  timeout" decision above.
- `Delete` and `Save`, which previously ignored their `context.Context`, now
  thread it into the dial like the other operations.

---
