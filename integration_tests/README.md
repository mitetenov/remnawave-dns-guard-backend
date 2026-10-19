# Backend compatibility checks

Build the backend, then exercise its real HTTP listener with the standard Python
library. Python and its old service dependencies are not part of the image.

```sh
go build -o /tmp/dns-guard-backend ./cmd/dns-guard
DNS_GUARD_BACKEND_BINARY=/tmp/dns-guard-backend \
  python3 -m unittest discover -s integration_tests -v
```

The suite starts separate backend processes on temporary loopback ports, creates
temporary SQLite databases, and stops them after each test. It never opens the
operator's `.env`, existing database, or running local services.

It checks the existing frontend's authentication, forms, response shapes and
sanitized errors; the agent's lease, replay, control-outage, profile-change and
inconclusive-result behavior; encrypted Python data migration; credential-based
session revocation; persistence after process restarts; and draining an active
HTTP request before SQLite closes on SIGTERM. Provider requests are
not needed: integration error paths use unconfigured integrations, and the legacy
fixture has no pending actions, disabled automation and a future DNS scan time.
Provider adapters and DNS mutations are covered separately by the Go test suite.

`fixtures/legacy_python.sql` is a fixed, inert compatibility fixture using the
retired Python SQLite schema and Python `cryptography.fernet.Fernet` tokens. Its
test-only APP_SECRET is 32 `S` characters. Its stored session digest belongs to
`python-session-cookie-v1`, with credentials `админ` / `пароль`; the auth revision
was calculated with the Python `json.dumps` default Unicode escaping and spacing.
Those non-ASCII credentials catch accidental changes to the revision algorithm.
The fixture deliberately lacks the later target observation/action columns, so
the same test proves the automatic additive migration preserves existing data.

The black-box scenarios were also run unchanged against the saved Python
implementation while developing the Go replacement. The historical backend is
not needed to run these checks.

With a checkout of the Go agent available beside the backend, the optional real
Go-to-Go wire test checks two batches covering eight targets, control loss before
submission, a missing local Xray binary, and shared Unicode/public-IP validation:

```sh
GO_BINARY=/path/to/go python3 integration_tests/go_wire/run.py --agent ../agent
```

That runner builds an isolated temporary module using both local checkouts. It
replaces provider/probe network work with deterministic fakes and does not add a
cross-repository runtime dependency to either service.
