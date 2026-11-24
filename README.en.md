[繁體中文](README.md) | **English**

# opcua

An OPC UA server and client for industrial controllers, written in pure Go.

Made to run on controllers and gateways: it exposes field points as `ns=2;s=<point name>` to SCADA, BMS and MES systems for reading, writing and subscriptions, with alarms and history, and connects as a client to PLCs and other OPC UA servers.

- **Pure Go, no cgo**: one `CGO_ENABLED=0` build for Windows amd64, Linux amd64 and Linux armv7.
- **Secure by default**: the server accepts only the security combinations you enable and cannot be downgraded to None; client certificates go through a trust list; anonymous users are read-only by default.
- **Full server**: read/write, browse, subscriptions (with deadband and Republish), methods, events, Alarms & Conditions, history (Raw, AtTime, Processed, Events).
- **Practical client**: picks the most secure endpoint, batch reads, writes with automatic type conversion, reconnects on its own.

## Installing

```
go get github.com/ka1hung/opcua
```

Needs Go 1.23 or later.

## Quick start

### Server

```go
cert, key, _, _, err := certs.LoadOrCreate("pki/own/cert.der", "pki/own/key.pem",
	certs.Spec{ApplicationURI: "urn:host:app", Hosts: []string{"192.168.1.10"}}, true)
store, err := certs.Open("pki", certs.Options{})

srv := server.New(
	server.Certificate(cert), server.PrivateKey(key),
	server.EndPoint("192.168.1.10", 4840), server.ListenAddress("0.0.0.0:4840"),
	server.EnableSecurity("None", ua.MessageSecurityModeNone),
	server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
	server.EnableAuthMode(ua.UserTokenTypeAnonymous), // anonymous is read-only
	server.EnableAuthMode(ua.UserTokenTypeUserName),
	server.UserNameAuthenticator(func(ctx context.Context, user, pass string) (*server.Identity, error) { ... }),
	server.TrustStore(store),
)

ns := srv.AddNamespace("urn:host:app:points") // the first custom namespace is always ns=2
folder, _ := srv.AddFolder(server.ObjectsFolder, ua.NewStringNodeID(ns, "Points"), "Points")
srv.AddVariable(folder.ID(), server.VariableSpec{
	NodeID: ua.NewStringNodeID(ns, "AHU01_Temp"), BrowseName: "AHU01_Temp",
	DataType: ua.TypeIDDouble, Writable: true, Unit: "°C", EURange: &server.Range{Low: 0, High: 50},
	CanWrite: func(who *server.Identity) bool { return who.UserName == "admin" },
})
srv.OnWrite(func(ctx context.Context, who *server.Identity, node *ua.NodeID, v *ua.Variant) ua.StatusCode { ... })
srv.Start(ctx)

// when field data changes
srv.SetValue(ua.NewStringNodeID(ns, "AHU01_Temp"), 21.5, ua.StatusOK, time.Now())
srv.SetAlarm(server.Alarm{Source: id, Name: "High", Active: true, Severity: 700, Message: "AHU01 temperature high"})
```

### Client

```go
c, err := client.Dial(ctx, "opc.tcp://plc:4840", client.Options{
	Security: client.Auto(client.MinSign), // fails if no endpoint is secure enough; never falls back to None
	Auth:     client.UserPass("user", "pw"),
})
results := c.ReadMany(ctx, []string{"ns=2;s=A", "ns=2;s=B"})
err = c.WriteAuto(ctx, "ns=2;s=Setpoint", 23)
sub, _, err := c.Subscribe(ctx, ids, 500*time.Millisecond, func(id string, r client.Result) { ... })
```

The client covers what the server offers:

| Server offers | Client |
|---|---|
| Endpoints and security | `client.Endpoints` (list endpoints before connecting), `Dial` |
| Read and write | `ReadMany`, `WriteAuto`, `Attributes` (data type, access, description and more) |
| Browse | `Browse`, `Translate` (find a node by path) |
| Subscriptions | `Subscribe`, `SubscribeWith` (deadband, queue, sampling, trigger) |
| Methods | `MethodArguments`, `Call` (arguments converted to the method's types) |
| Events and alarms | `SubscribeEvents`, `Refresh` (alarms already active), `Acknowledge` |
| History | `HistoryRaw`, `HistoryAtTime`, `HistoryProcessed`, `HistoryEvents` |
| Server information | `ServerStatus`, `Namespaces` |

```go
events, err := c.SubscribeEvents(ctx, client.ServerObject, time.Second, func(e client.Event) {
	if e.IsCondition() && e.Active && !e.Acked {
		_ = c.Acknowledge(ctx, e, "handled")
	}
})
_ = events.Refresh(ctx) // also send the alarms that were active before connecting

out, err := c.Call(ctx, "ns=2;s=Plant", "ns=2;s=Plant.Reset", "maintenance")
avg, err := c.HistoryProcessed(ctx, "ns=2;s=AHU01_Temp", client.Average, start, end, 10*time.Minute)
```

## Layout

| Path | Contents |
|---|---|
| `server/` | Server |
| `client/` | High-level client (use this one in applications) |
| `certs/` | Self-signed certificates, trust list (trusted / issuers / rejected folders) |
| `ua/`, `uasc/`, `uacp/`, `uapolicy/` | Encoding, secure channel, transport, security policies |
| root (`opcua`) | Low-level client that `client/` is built on |
| `cmd/id/`, `cmd/service/`, `cmd/status/`, `schema/` | Generate `ua/` and `id/` code from the OPC UA specification files (`go generate`) |
| `tests/` | Integration and conformance tests |
| `docs/` | Change log against gopcua, interop results |

## Test tool

The simulated server, field diagnostics and load tests live in a separate project, **uatester** (`ka1hung/uatester`): a Windows desktop app and the `uatest` command line tool, which also runs on armv7.

## Testing

```
go test ./...                                  # unit tests
go test -tags=integration ./tests/go/...       # client against this server
go test -tags=conformance ./tests/...          # conformance tests
scripts/fuzz.sh 1h                             # fuzz, one hour per target
```

`-race` needs a C compiler (cgo); on Windows without one, rely on the GitHub Actions run.

## Documents

- [docs/CHANGES.md](docs/CHANGES.md): every difference from the gopcua base; each lower-layer change is logged so upstream security fixes can be compared later (Chinese only)
- [docs/interop.md](docs/interop.md): interop results and the UaExpert manual checklist (Chinese only)
- [tests/README.en.md](tests/README.en.md): the larger tests and how they are written
- [CHANGELOG.en.md](CHANGELOG.en.md): release history

## Credits

This package stands on two open-source projects:

- **[gopcua/opcua](https://github.com/gopcua/opcua)** (MIT): this project branched from its v0.9.2 (commit `b76fd80`). Encoding, transport, secure channel, security policies and the low-level client come from gopcua, with the server-side security checks strengthened; the server was rewritten from the OPC UA specification.
- **[awcullen/opcua](https://github.com/awcullen/opcua)** (MIT): reference for the server's feature scope and API design (methods, events, authentication, history). Only the design was consulted; none of its code is used.

This project is maintained independently and does not contribute upstream; please do not report its issues to either project.

## License

MIT; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Files inherited from gopcua keep their original copyright notices.
