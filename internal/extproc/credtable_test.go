package extproc

import (
	"context"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	clrkv1alpha1 "github.com/apoxy-dev/clrk/api/clrk/v1alpha1"
	"github.com/apoxy-dev/clrk/internal/egress"
)

// Dummy credential values. They are distinct so a test can tell which
// policy's Secret reached a request, and recognizable so a leak into a
// record is easy to grep for.
const (
	tokenA       = "Bearer dummy-token-a"
	tokenB       = "Bearer dummy-token-b"
	tokenGateway = "Bearer dummy-token-gateway"
	tokenGWExtra = "dummy-gateway-extra"
	placeholder  = "Bearer agent-placeholder"
)

var testEG = types.NamespacedName{Namespace: "default", Name: "eg"}

func testSecret(name, value string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
		Data:       map[string][]byte{"token": []byte(value)},
	}
}

func headerCIP(name, kind, target, secret, header string) clrkv1alpha1.CredentialInjectionPolicy {
	return clrkv1alpha1.CredentialInjectionPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, ResourceVersion: "1"},
		Spec: clrkv1alpha1.CredentialInjectionSpec{
			TargetRefs: []gwapiv1a2.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gwapiv1a2.LocalPolicyTargetReference{
					Group: clrkAPIGroup,
					Kind:  gwapiv1.Kind(kind),
					Name:  gwapiv1.ObjectName(target),
				},
			}},
			SecretRef:  gwapiv1.SecretObjectReference{Name: gwapiv1.ObjectName(secret)},
			SecretKey:  "token",
			Target:     clrkv1alpha1.CredentialTargetHeader,
			HeaderName: ptr.To(header),
		},
	}
}

func testL4Route(name, eg string, matches ...clrkv1alpha1.L4RouteMatch) clrkv1alpha1.EgressL4Route {
	return clrkv1alpha1.EgressL4Route{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, ResourceVersion: "1"},
		Spec: clrkv1alpha1.EgressL4RouteSpec{
			ParentRefs: []gwapiv1.ParentReference{{Name: gwapiv1.ObjectName(eg)}},
			Rules:      []clrkv1alpha1.EgressL4RouteRule{{Matches: matches}},
		},
	}
}

func hostPortMatch(host string, port int32) clrkv1alpha1.L4RouteMatch {
	return clrkv1alpha1.L4RouteMatch{
		DestinationHostnames: []gwapiv1.Hostname{gwapiv1.Hostname(host)},
		Ports:                []clrkv1alpha1.L4PortMatch{{Port: ptr.To(port)}},
	}
}

// scopedFixture is two upstreams on different host:port pairs, each with
// its own EgressL4Route and credential, plus (optionally) an unscoped
// EgressGateway credential setting the same header and one setting
// another header.
type scopedFixture struct {
	client   client.Client
	l4Routes []clrkv1alpha1.EgressL4Route
	cips     []clrkv1alpha1.CredentialInjectionPolicy
}

func newScopedFixture(t *testing.T, withGateway bool) *scopedFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		testSecret("cred-a", tokenA),
		testSecret("cred-b", tokenB),
		testSecret("cred-gateway", tokenGateway),
		testSecret("cred-gateway-extra", tokenGWExtra),
	).Build()
	f := &scopedFixture{
		client: c,
		l4Routes: []clrkv1alpha1.EgressL4Route{
			testL4Route("upstream-a", "eg", hostPortMatch("api.example.com", 443)),
			testL4Route("upstream-b", "eg", hostPortMatch("registry.internal", 8443)),
			// Attached to another gateway: a CIP targeting it must not
			// apply on testEG even though the destination matches.
			testL4Route("detached", "other-eg", hostPortMatch("detached.example.com", 443)),
		},
		cips: []clrkv1alpha1.CredentialInjectionPolicy{
			headerCIP("cred-a", egressL4RouteKind, "upstream-a", "cred-a", "Authorization"),
			headerCIP("cred-b", egressL4RouteKind, "upstream-b", "cred-b", "Authorization"),
			headerCIP("cred-detached", egressL4RouteKind, "detached", "cred-a", "Authorization"),
		},
	}
	if withGateway {
		f.cips = append(f.cips,
			headerCIP("cred-gateway", egressGatewayKind, "eg", "cred-gateway", "Authorization"),
			headerCIP("cred-gateway-extra", egressGatewayKind, "eg", "cred-gateway-extra", "X-Extra"),
		)
	}
	return f
}

func (f *scopedFixture) table(t *testing.T) *credTable {
	t.Helper()
	return buildCredTable(context.Background(), f.client, testEG.Namespace, testEG.Name, nil, f.l4Routes, f.cips)
}

// injectedHeaders flattens injections into the header map they produce.
func injectedHeaders(injs []credInjection) map[string]string {
	out := map[string]string{}
	for _, inj := range injs {
		if inj.sigv4 == nil {
			out[inj.headerName] = inj.headerValue
		}
	}
	return out
}

// mutationHeaders flattens a HeaderMutation's SetHeaders into a map.
func mutationHeaders(m *extprocv3.HeaderMutation) map[string]string {
	out := map[string]string{}
	for _, h := range m.GetSetHeaders() {
		out[h.GetHeader().GetKey()] = string(h.GetHeader().GetRawValue())
	}
	return out
}

func TestDestFromAuthority(t *testing.T) {
	tests := []struct {
		authority string
		want      credDest
	}{
		{"api.example.com", credDest{"api.example.com", 443}},
		{"api.example.com:443", credDest{"api.example.com", 443}},
		{"registry.internal:8443", credDest{"registry.internal", 8443}},
		{"[2001:db8::1]:8443", credDest{"2001:db8::1", 8443}},
		{"", credDest{}},
		{"api.example.com:0", credDest{}},
		{"api.example.com:99999", credDest{}},
	}
	for _, tt := range tests {
		if got := destFromAuthority(tt.authority); got != tt.want {
			t.Errorf("destFromAuthority(%q) = %+v, want %+v", tt.authority, got, tt.want)
		}
	}
}

func TestCredLookupScopedToDestination(t *testing.T) {
	tbl := newScopedFixture(t, false).table(t)
	tests := []struct {
		name      string
		authority string
		want      string // expected authorization value, "" for none
	}{
		{"host A, implicit 443", "api.example.com", tokenA},
		{"host A, explicit 443", "api.example.com:443", tokenA},
		{"host A, case-insensitive", "API.Example.com", tokenA},
		{"host B", "registry.internal:8443", tokenB},
		// The port is part of the destination: B's credential is scoped
		// to 8443 and must not reach registry.internal:443, and A's is
		// scoped to 443 and must not reach api.example.com:8443.
		{"host B on the default port", "registry.internal", ""},
		{"host A on another port", "api.example.com:8443", ""},
		{"subdomain of A", "x.api.example.com", ""},
		{"unrelated host", "elsewhere.example.com", ""},
		{"route attached to another gateway", "detached.example.com", ""},
		{"no authority", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := injectedHeaders(tbl.lookup(nil, destFromAuthority(tt.authority)))["authorization"]
			if got != tt.want {
				t.Fatalf("authorization = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCredLookupGatewayIsCatchAll(t *testing.T) {
	tbl := newScopedFixture(t, true).table(t)
	tests := []struct {
		authority string
		want      map[string]string
	}{
		// A narrower EgressL4Route policy setting the same header wins
		// over the gateway; the gateway still fills headers nothing
		// narrower sets.
		{"api.example.com", map[string]string{"authorization": tokenA, "x-extra": tokenGWExtra}},
		{"registry.internal:8443", map[string]string{"authorization": tokenB, "x-extra": tokenGWExtra}},
		// No scoped match: the unscoped gateway policy applies as before.
		{"elsewhere.example.com", map[string]string{"authorization": tokenGateway, "x-extra": tokenGWExtra}},
	}
	for _, tt := range tests {
		got := injectedHeaders(tbl.lookup(nil, destFromAuthority(tt.authority)))
		if len(got) != len(tt.want) {
			t.Errorf("%s: got %v, want %v", tt.authority, got, tt.want)
			continue
		}
		for k, v := range tt.want {
			if got[k] != v {
				t.Errorf("%s: %s = %q, want %q", tt.authority, k, got[k], v)
			}
		}
	}
}

func TestCredLookupPrecedence(t *testing.T) {
	hdr := func(policy, name, value string) credInjection {
		return credInjection{policyName: policy, headerName: name, headerValue: value}
	}
	section := func(inj credInjection, s string) credInjection { inj.section = s; return inj }
	sigv4 := credInjection{policyName: "default/sigv4", sigv4: &sigv4Cred{service: "bedrock"}}
	route := testL4Route("r", "eg", hostPortMatch("api.example.com", 443))
	rr := &routeRule{routeNamespace: "default", routeName: "apr"}
	dest := credDest{"api.example.com", 443}

	tbl := &credTable{
		byRoute: map[types.NamespacedName][]credInjection{{Namespace: "default", Name: "apr"}: {
			section(hdr("default/backend", "authorization", "backend"), "b1"),
			hdr("default/route", "authorization", "route"),
			hdr("default/route-extra", "x-route", "route-extra"),
		}},
		byDestination: []destCredInjection{
			{inj: hdr("default/dest", "authorization", "dest"), matcher: egress.NewDestinationMatcher(route)},
			{inj: hdr("default/dest-extra", "x-dest", "dest-extra"), matcher: egress.NewDestinationMatcher(route)},
		},
		gateway: []credInjection{
			hdr("default/gw", "authorization", "gw"),
			hdr("default/gw-extra", "x-gw", "gw-extra"),
		},
	}

	tests := []struct {
		name    string
		rr      *routeRule
		backend string
		dest    credDest
		want    map[string]string
	}{
		{"backend section beats route-wide, destination and gateway", rr, "b1", dest,
			map[string]string{"authorization": "backend", "x-route": "route-extra", "x-dest": "dest-extra", "x-gw": "gw-extra"}},
		{"route-wide beats destination and gateway", rr, "", dest,
			map[string]string{"authorization": "route", "x-route": "route-extra", "x-dest": "dest-extra", "x-gw": "gw-extra"}},
		{"destination beats gateway", nil, "", dest,
			map[string]string{"authorization": "dest", "x-dest": "dest-extra", "x-gw": "gw-extra"}},
		{"gateway alone", nil, "", credDest{"other.example.com", 443},
			map[string]string{"authorization": "gw", "x-gw": "gw-extra"}},
		{"unknown destination skips destination scope", nil, "", credDest{},
			map[string]string{"authorization": "gw", "x-gw": "gw-extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injs := tbl.lookupForBackend(tt.rr, tt.backend, tt.dest)
			got := injectedHeaders(injs)
			if len(got) != len(tt.want) || len(injs) != len(tt.want) {
				t.Fatalf("got %v (%d injections), want %v", got, len(injs), tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
		})
	}

	// An AWSv4 signature sets Authorization: a narrower SigV4 policy
	// suppresses a broader static Authorization header and vice versa.
	tbl.byDestination[0].inj = sigv4
	injs := tbl.lookup(nil, dest)
	for _, inj := range injs {
		if inj.headerName == "authorization" {
			t.Fatalf("gateway authorization applied alongside a narrower SigV4 policy: %+v", injs)
		}
	}
	if len(injs) == 0 || injs[0].sigv4 == nil {
		t.Fatalf("SigV4 destination policy dropped: %+v", injs)
	}
}

// newTestDownstream builds a downstream stream wired to tbl, the way
// Server.newDownstreamStream does from the registry.
func newTestDownstream(tbl *credTable) *downstreamStream {
	srv := New(nil)
	ds := &downstreamStream{
		srv:             srv,
		logger:          logr.Discard(),
		rec:             Record{Timestamp: time.Now()},
		sink:            slogSink{},
		maxCaptureBytes: 64 * 1024,
		creds:           tbl,
	}
	ds.reqBytesLeft = ds.maxCaptureBytes
	ds.respBytesLeft = ds.maxCaptureBytes
	return ds
}

func requestHeaders(kv ...string) *extprocv3.HttpHeaders {
	hm := &corev3.HeaderMap{}
	for i := 0; i+1 < len(kv); i += 2 {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	return &extprocv3.HttpHeaders{Headers: hm}
}

// TestHeaderTimeInjectionFollowsAuthority drives onRequestHeaders the way
// Envoy does after TLS termination. The ext_proc only ever sees the
// :authority the request carries (Envoy maps HTTP/1.1 Host onto it), and
// that is what the dynamic forward proxy dials and derives the upstream
// SNI from. The agent's downstream SNI picked the leaf certificate and
// nothing else, so a request opened for host A carrying host B's
// authority is sent to B and must get B's credential, never A's — in
// both directions.
func TestHeaderTimeInjectionFollowsAuthority(t *testing.T) {
	tbl := newScopedFixture(t, false).table(t)
	tests := []struct {
		name      string
		authority string
		want      string
	}{
		{"TLS opened for A, Host B", "registry.internal:8443", tokenB},
		{"TLS opened for B, Host A", "api.example.com", tokenA},
		{"Host B without B's port", "registry.internal", ""},
		{"unmatched host keeps the placeholder", "elsewhere.example.com", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := newTestDownstream(tbl)
			resp := ds.onRequestHeaders(requestHeaders(
				":method", "GET",
				":authority", tt.authority,
				":path", "/v1/whoami",
				"authorization", placeholder,
			), time.Now())
			set := mutationHeaders(resp.GetRequestHeaders().GetResponse().GetHeaderMutation())
			got, injected := set["authorization"]
			if tt.want == "" {
				if injected {
					t.Fatalf("authorization injected (%q); want the placeholder to pass through", got)
				}
				if ds.rec.RequestHeaders["authorization"] != placeholder {
					t.Fatalf("captured authorization = %q, want the untouched placeholder", ds.rec.RequestHeaders["authorization"])
				}
				return
			}
			if got != tt.want {
				t.Fatalf("injected authorization = %q, want %q", got, tt.want)
			}
			if ds.rec.RequestHeaders["authorization"] != "<redacted>" {
				t.Fatalf("captured authorization = %q, want <redacted>", ds.rec.RequestHeaders["authorization"])
			}
			assertNoSecretInRecord(t, ds.rec)
		})
	}
}

func TestInjectFallbackCredsScopedToHeaderAuthority(t *testing.T) {
	tbl := newScopedFixture(t, false).table(t)
	headers := map[string]string{":method": "POST", ":authority": "registry.internal:8443", "authorization": placeholder}
	mut := injectFallbackCreds(tbl, nil, headers, nil, "/v1/x", logr.Discard())
	if got := mutationHeaders(mut)["authorization"]; got != tokenB {
		t.Fatalf("fallback authorization = %q, want %q", got, tokenB)
	}
	if headers["authorization"] != "<redacted>" {
		t.Fatalf("captured authorization = %q, want <redacted>", headers["authorization"])
	}

	headers = map[string]string{":method": "POST", ":authority": "elsewhere.example.com", "authorization": placeholder}
	if mut := injectFallbackCreds(tbl, nil, headers, nil, "/v1/x", logr.Discard()); mut != nil {
		t.Fatalf("fallback injected for an unmatched destination: %v", mutationHeaders(mut))
	}
}

// TestUpstreamAttemptScopedToSelectedBackend checks the per-attempt path:
// an attempt re-pointed to a selected Backend gets the credential scoped
// to that Backend's host:port, not the one scoped to the agent's original
// :authority.
func TestUpstreamAttemptScopedToSelectedBackend(t *testing.T) {
	tbl := newScopedFixture(t, false).table(t)
	rr := &routeRule{routeNamespace: "default", routeName: "apr", backends: []resolvedBackend{
		{namespace: "default", name: "b", host: "registry.internal", port: 8443},
		{namespace: "default", name: "other", host: "other.example.com", port: 443},
	}}
	for _, tt := range []struct {
		cand int
		want string
	}{{0, tokenB}, {1, ""}} {
		us := &upstreamStream{
			srv:        New(nil),
			logger:     logr.Discard(),
			creds:      tbl,
			method:     "GET",
			path:       "/v1/models",
			reqHeaders: map[string]string{":authority": "api.example.com"},
			state:      &requestState{rule: rr},
			cand:       &rr.backends[tt.cand],
		}
		resp := us.commitBodyless()
		set := mutationHeaders(resp.GetRequestHeaders().GetResponse().GetHeaderMutation())
		if got := set["authorization"]; got != tt.want {
			t.Errorf("backend %s: authorization = %q, want %q", rr.backends[tt.cand].name, got, tt.want)
		}
	}
}

func TestCredPoliciesVersionTracksScopingRoute(t *testing.T) {
	f := newScopedFixture(t, false)
	ctx := context.Background()
	base := CredPoliciesVersion(ctx, f.client, f.cips, nil, f.l4Routes, testEG)
	if !strings.Contains(base, "default/upstream-a@1") {
		t.Fatalf("fingerprint %q lacks the scoping route's version", base)
	}
	if strings.Contains(base, "cred-detached") {
		t.Fatalf("fingerprint %q includes a CIP whose route attaches to another gateway", base)
	}

	edited := append([]clrkv1alpha1.EgressL4Route(nil), f.l4Routes...)
	edited[1].ResourceVersion = "2"
	if v := CredPoliciesVersion(ctx, f.client, f.cips, nil, edited, testEG); v == base {
		t.Fatal("editing a scoping route did not change the fingerprint")
	}

	unrelated := append([]clrkv1alpha1.EgressL4Route(nil), f.l4Routes...)
	unrelated[2].ResourceVersion = "2"
	if v := CredPoliciesVersion(ctx, f.client, f.cips, nil, unrelated, testEG); v != base {
		t.Fatal("editing a route attached to another gateway changed the fingerprint")
	}

	detached := append([]clrkv1alpha1.EgressL4Route(nil), f.l4Routes...)
	detached[0].Spec.ParentRefs = []gwapiv1.ParentReference{{Name: "other-eg"}}
	if v := CredPoliciesVersion(ctx, f.client, f.cips, nil, detached, testEG); strings.Contains(v, "default/cred-a@") {
		t.Fatalf("fingerprint %q still includes a CIP whose route detached", v)
	}
}

func assertNoSecretInRecord(t *testing.T, rec Record) {
	t.Helper()
	for k, v := range rec.RequestHeaders {
		for _, secret := range []string{tokenA, tokenB, tokenGateway, tokenGWExtra} {
			if strings.Contains(v, secret) {
				t.Fatalf("record header %s carries a secret value", k)
			}
		}
	}
}
