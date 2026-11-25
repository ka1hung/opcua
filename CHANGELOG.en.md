[繁體中文](CHANGELOG.md) | **English**

# Changelog

Every difference from the gopcua base is listed in [docs/CHANGES.md](docs/CHANGES.md) (Chinese only).

## Unreleased (v0.2.3)

- Client `Subscribe` takes any number of nodes: items are created in calls of at most the server's MaxMonitoredItemsPerCall, and another subscription is opened when one is full (Bad_TooManyMonitoredItems). Before, all items went in one call and failed above the server's limit. `Subscription.Count()` reports how many subscriptions are used.
- Client accepts node ids in the form `nsu=<namespace URI>;<id>` everywhere, so they survive a change of the server's namespace order; `Client.NSU` converts `ns=` ids.
- Client `Options.VerifyServer` checks the server certificate before connecting (e.g. trust on first use); `Options.ApplicationName`; `EndpointInfo.Thumbprint` and `CertThumbprint`.
- Server: `Server.SessionOf(ctx)` tells write, method and acknowledge callbacks which client called; `SessionInfo` adds ClientName, ClientAddr, Created and MonitoredItems; `Server.CloseSession`.
- Trust list: `certs.Store` adds `Trusted`, `Untrust` and `DeleteRejected`.

## v0.2.2 (2026-11-25)

Security fixes (thanks to a private report):

- **Decoder recursion depth** (DoS before authentication): Variant, DataValue, DiagnosticInfo and ExtensionObject can nest without end, so a message under 2 MiB could overflow the server's stack and end the process (recover cannot stop a stack overflow). Nesting is now limited to 100 levels; deeper messages fail with `BadEncodingLimitsExceeded`.
- **IndexRange overflow**: an IndexRange whose upper bound was the largest int panicked on the next value change, in a goroutine without recover, ending the server; on 32-bit (armv7) the trigger value is just `2147483647`.
- **Client certificate binding**: the client accepted a different server certificate in an OpenSecureChannel response, so the TrustStore protected only the first connection; on an automatic reconnect a man in the middle could impersonate the server and receive the user's password. The response's certificate and security policy must now match those the channel was opened with; the server certificate in CreateSession must be the channel's, and a failed signature check now returns an error (it used to be only logged).
- **Read access in subscriptions**: pushed monitored items (variables added with `AddVariable`) checked `CanRead` only when created, so a subscription kept receiving new values after read access was taken away. Every value is now checked; a denied user gets `BadUserAccessDenied`, and values resume when access returns.
- **Certificate revocation**: a CA-issued certificate trusted individually (in `trusted/certs`) was not checked against a CRL, and `RequireCRL` had no effect, so it kept connecting after its CA revoked it. Its revocation is now checked against its issuer's CRL; if the issuer is not known, `RequireCRL` rejects it.

## v0.2.1 (2026-11-24)

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
