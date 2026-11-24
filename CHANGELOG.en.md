[繁體中文](CHANGELOG.md) | **English**

# Changelog

Every difference from the gopcua base is listed in [docs/CHANGES.md](docs/CHANGES.md) (Chinese only).

## Unreleased

- Client fix: when a server advertises an endpoint URL with a host name the client cannot resolve (common in the field), the client connects to the host it dialled, keeping the advertised port and path; it used to fail on the DNS lookup.

## v0.2.0 (2026-11-24)

- Server: `Server.AddReference` adds a reference between two existing nodes (for example, so a legacy folder lists the same point without copying the node).

## v0.1.0 (2026-11-24)

First public release, based on gopcua v0.9.2.

- Secure channel hardening: no security downgrade, client certificate validation with PKI folders, chunk limits, protection against remote panics.
- Server rewrite: address space, read/write, browse, subscriptions, authentication and permissions, methods, events, Alarms & Conditions, history (Raw, AtTime, Processed, Events). An area object receives the events and alarms of the points below it; ConditionRefresh keeps each alarm's EventId, so several clients can acknowledge alarms.
- New high-level client package `client`, matching the server: read/write, browse, node attributes, subscriptions (deadband, queue, trigger), method calls, events and alarms (subscribe, Refresh, acknowledge), history, server status, endpoint list.
- Test tools live in the separate [uatester](https://github.com/ka1hung/uatester) project.
