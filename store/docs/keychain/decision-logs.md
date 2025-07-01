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
