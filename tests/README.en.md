[繁體中文](README.md) | **English**

# Tests

This folder holds the larger tests: the ones that need a separate server, a scripted misbehaving peer, or a third-party implementation. Ordinary unit tests live next to their packages (for example `server/p1_test.go`) and run with `go test ./...`. The tests here only run with a build tag; CI runs them on every push.

## Running

```
go test -tags=integration ./tests/go/...       # low-level client ↔ this server
go test -tags=integration ./tests/python/...   # low-level client ↔ Python opcua server (needs pip3 install opcua)
go test -tags=conformance ./tests/...          # everything else (specification behaviour)
```

- `-race` needs a C compiler (cgo). On Windows without one, rely on the GitHub Actions run.
- `tests/go` always uses port 4840; do not run it alongside anything else on 4840.

## Folders

| Folder | What it tests | Runs against | Tests |
|---|---|---|---|
| `go/` | Read/write, namespaces, secure connections, PKCS#8 keys, stats | this server | 8 |
| `python/` | Read/write, methods, reconnect, timeouts, unknown nodes; currently the only interop test with a third-party stack | Python opcua server | 9 |
| `reconnect/` | Whether notifications are lost across a drop, subscriptions recover, Republish, when a new session is created | scripted server that can drop the connection on cue | 15 |
| `securechannel/` | Token lifetime measured from receipt, a ServiceFault keeps the channel open, expired tokens are rejected, sequence numbers are verified | scripted server | 4 |
| `securitypolicy/` | Every RSA-OAEP block is filled when opening a channel; the client nonce under policy None | scripted server | 2 |
| `session/` | Which policy encrypts a user name token (empty means the channel's; with several, the endpoint's own) | this server with ActivateSession replaced by a recorder | 2 |
| `transport/` | The TCP handshake gives up at its deadline or on cancel; a host name with several addresses moves on to the next | silent peer that never answers | 3 |
| `encoding/` | Encoding edge cases: DateTime range, null values, forged Variant array lengths and dimensions | no connection; calls `ua.Encode` / `ua.Decode` directly | 9 |
| `server/` | The client keeps working across key renewals; `SetValue` on a subscribed point does not block | this server | 2 |
| `internal/scriptedpeer/` | Not tests: the scripted-server core shared by `transport`, `securitypolicy` and `securechannel` | — | — |

## Conventions

**One behaviour per file.** The file name is that behaviour as an English sentence, for example `expired_security_token_is_rejected_test.go`, and the file holds one `func Test`.

**The opening comment covers, in order:**
1. The behaviour, quoting the specification clause (for example OPC 10000-4 §5.13).
2. How it differs from neighbouring tests.
3. What it runs against, ending with `See harness.go.` (check: `grep -c "See harness.go" tests/<folder>/*_test.go` prints 1 for every test file).
4. What it asserts, and what it deliberately does not.
5. Which other implementations were read (open62541, UA-.NETStandard, Eclipse Milo, node-opcua).

**Where code goes:**
- Code shared by two or more tests in a folder goes in `harness.go`.
- A helper used by one test lives with that test.
- Code shared by two or more folders goes in `internal/`.
- Helpers return values; only the `Test` function calls `t.Errorf` / `t.Fatalf`.

**Three outcomes; the last two both fail CI:**

| Outcome | Meaning | How |
|---|---|---|
| Pass | The library behaves correctly | — |
| Fail | The library is wrong, or its own error made the run unscoreable | `t.Errorf` |
| Could not score | The environment failed: port in use, scripted server error, a slow machine overran a bound | `t.Fatalf("could not set the test up: ...")` |

**The verdict must rest on evidence from outside the code under test.** Encoding a value and decoding it with the same library only shows the library agrees with itself; a bug on both sides passes. So verdicts rest on:
- bytes written out in the test (taken from the specification or another stack, with the source named in the header);
- the Go standard library, for example decrypting with `crypto/rsa`;
- the race detector, or a clock (a deadline scores a hang);
- what the scripted server actually recorded on the wire.

## Behaviour not fixed yet (knownBug)

A test for behaviour the specification requires but the library does not have yet declares a `knownBug` constant:
- The test runs, and a failure prints `known bug:` without failing CI.
- Once fixed, the test passes and **deliberately reports an error** telling you to delete the constant and everything only it used, in the same commit as the fix.
- If it starts passing and you cannot say why, do not delete the constant; find out first.

One stands today: `reconnect/no_acknowledgements_when_nothing_is_available_test.go`. The client still acknowledges when the server keeps no retransmission queue (its availableSequenceNumbers is empty).

## Questions for reviewing a new test

A test that passes while checking nothing is worse than none, because people trust it.

1. Can the failing branch ever run? Trace it.
2. Does the result depend on the code under test, or on the fixture's own state?
3. Before deleting a branch that looks unreachable, check whether a correct implementation would reach it.
4. Does it compile against the unfixed code? A test that fails only because a new function is missing tests a name, not a behaviour.
5. Was the condition constructed, or hoped for?
6. Would a known-good implementation (read its source) fail it too? If so, the test is the likely mistake.

## Not tested yet

**reconnect** (client behaviour in OPC 10000-4 §6.7), blocked on what the scripted server cannot do yet:
- Failed ActivateSession: create a new session only when activation fails; recreate subscriptions when TransferSubscriptions fails. The scripted server grants every activation today.
- Reconnecting on a secured endpoint with the same policy, application certificate and user.
- Calling GetEndpoints after a channel-level certificate error.
- Recovering data with the ResendData method.
- Detecting a connection that stays open but goes silent, through the subscription keep-alive.
- Reverse connect.
- The race between the client's internal pause and resume signals (gopcua issue #895): a goroutine scheduling problem that a black-box test cannot see; it needs a different kind of test.

Two items are the application's job, not the library's, so they are not tests here: subscribing to ServerStatus to detect shutdown, and keeping older Republish values from overwriting newer ones.

**session**: endpoints in mode None must not use ECC / RSA_DH policies. The library implements no ECC / RSA_DH policy yet; add the test when it does.
