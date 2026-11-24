[繁體中文](CHANGELOG.md) | **English**

# Changelog

Every difference from the gopcua base is listed in [docs/CHANGES.md](docs/CHANGES.md) (Chinese only).

## Unreleased

- **32-bit (armv7) fix**: 64-bit counters in the secure channel and monitor were not aligned on 32-bit platforms, so the first service request panicked and the connection was closed (clients saw BadTCPInternalError). CI now runs the tests as 32-bit too.
- Server: when a client connects by an address that is not in the configured list (for example by IP while the server is configured with its host name), the returned endpoint URLs use the client's address, so networks without DNS work.
- Client fix: when a server advertises an endpoint URL with a host name the client cannot resolve (common in the field), the client connects to the host it dialled, keeping the advertised port and path; it used to fail on the DNS lookup.

## v0.2.0 (2026-11-24)

- Server: `Server.AddReference` adds a reference between two existing nodes (for example, so a legacy folder lists the same point without copying the node).

## v0.1.0 (2026-11-24)

First public release, based on gopcua v0.9.2.

- Secure channel hardening: no security downgrade, client certificate validation with PKI folders, chunk limits, protection against remote panics.
- Server rewrite: address space, read/write, browse, subscriptions, authentication and permissions, methods, events, Alarms & Conditions, history (Raw, AtTime, Processed, Events). An area object receives the events and alarms of the points below it; ConditionRefresh keeps each alarm's EventId, so several clients can acknowledge alarms.
- New high-level client package `client`, matching the server: read/write, browse, node attributes, subscriptions (deadband, queue, trigger), method calls, events and alarms (subscribe, Refresh, acknowledge), history, server status, endpoint list.
- Test tools live in the separate [uatester](https://github.com/ka1hung/uatester) project.
