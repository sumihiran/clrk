# scoped-credentials

Demonstrates **destination-scoped credential injection**: one
`EgressGateway` allows two destinations, and each gets its own
credential. A `CredentialInjectionPolicy` that targets an
`EgressL4Route` injects only into requests whose destination matches
that route's rule matches; the same route is also the allowlist entry
the gateway enforces.

| Request from the agent                 | Injected `Authorization`        |
| -------------------------------------- | ------------------------------- |
| `https://api.example.com/...`          | `example-api-credentials`       |
| `https://registry.internal:8443/...`   | `internal-registry-credentials` |
| `https://registry.internal/...` (443)  | nothing (port doesn't match)    |

## Run under `clrk dev`

```bash
clrk dev --apply _examples/scoped-credentials/manifests
```

Point a TaskAgent or DaemonAgent at the gateway with
`egressRefs: [{gatewayRef: scoped-credentials}]` and have it send a
placeholder `Authorization` header (or none). The proxy replaces it on
the way out; the real value never enters the sandbox.

## How a destination is matched

- **Where the request goes, not the SNI.** The destination is the
  request's `:authority` (the HTTP/1.1 `Host` header) host and port,
  with 443 assumed when the agent omits the port. That is what the
  proxy dials. A request whose TLS session was opened for
  `api.example.com` but whose `Host` is `registry.internal:8443` is sent
  to the registry and gets the registry's credential, never the API's.
- **The route's own semantics.** `destinationHostnames` match exactly,
  or with a leading wildcard that covers exactly one label
  (`*.example.com` matches `api.example.com`, not `example.com` or
  `a.b.example.com`). `destinationCIDRs` match IP-literal destinations.
  `ports` take single ports and ranges. A match block with no criteria
  matches every destination.
- **Fail closed.** No match means no injection: the agent's
  placeholder passes through unchanged. A match block that uses
  `sourceAgents`, or carries an unparseable CIDR or port range, is
  ignored for credential scoping rather than widened, and the policy's
  status reports `Accepted=False` when no block of the route is usable.
- **Backends.** A request an `AIProviderRoute` re-points to a `Backend`
  is matched against that Backend's host and port.
- **Only HTTP.** Injection needs a listener that terminates TLS (or
  plain HTTP); TLS-passthrough and TCP listeners never inject.

Route edits apply without a restart.

## Precedence

Several policies can apply to one request. The narrowest wins per
header:

1. `AIProviderRoute` with a `sectionName` (one backend),
2. `AIProviderRoute` without one (route-wide),
3. `EgressL4Route` (destination-scoped),
4. `EgressGateway` (catch-all).

A broader policy is dropped when a narrower one sets any of the same
headers, and only fills in headers nothing narrower sets. Adding an
`EgressGateway`-targeted policy for `Authorization` to this example
would therefore inject it only into requests that neither route above
matches, while a gateway policy for a different header still applies
everywhere.

## Large responses

Response bodies whose content type is outside the gateway's capture
list (`spec.otlp.captureBody.includeContentTypes`, by default JSON,
NDJSON and SSE) stream through without being buffered, so package
downloads, archives and image layers of any size can be fetched through
the gateway. Their records carry `clrk.resp.body_skipped=true` and no
body or byte count.

Captured, non-streamed responses are still buffered whole before they
are released. Over HTTP/1.1 they can be at most the larger of
`captureBody.maxBytes` and 4 MiB (capped at 64 MiB); over HTTP/2 at most
the larger of that and 16 MiB. A larger captured response fails with
HTTP 500. No `ClientTrafficPolicy` is needed for these defaults; larger
values in one still win.
