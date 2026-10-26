package egress

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	clrkv1alpha1 "github.com/apoxy-dev/clrk/api/clrk/v1alpha1"
)

func l4Route(matches ...clrkv1alpha1.L4RouteMatch) clrkv1alpha1.EgressL4Route {
	return clrkv1alpha1.EgressL4Route{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "r"},
		Spec: clrkv1alpha1.EgressL4RouteSpec{
			ParentRefs: []gwapiv1.ParentReference{{Name: "eg"}},
			Rules:      []clrkv1alpha1.EgressL4RouteRule{{Matches: matches}},
		},
	}
}

func port(p int32) clrkv1alpha1.L4PortMatch { return clrkv1alpha1.L4PortMatch{Port: ptr.To(p)} }

func portRangeMatch(start, end int32) clrkv1alpha1.L4PortMatch {
	return clrkv1alpha1.L4PortMatch{StartPort: ptr.To(start), EndPort: ptr.To(end)}
}

func TestDestinationMatcherMatchAuthority(t *testing.T) {
	m := NewDestinationMatcher(l4Route(
		clrkv1alpha1.L4RouteMatch{
			DestinationHostnames: []gwapiv1.Hostname{"api.example.com"},
			Ports:                []clrkv1alpha1.L4PortMatch{port(443)},
		},
		clrkv1alpha1.L4RouteMatch{
			DestinationHostnames: []gwapiv1.Hostname{"*.svc.example.com"},
			Ports:                []clrkv1alpha1.L4PortMatch{portRangeMatch(9000, 9100)},
		},
		clrkv1alpha1.L4RouteMatch{
			DestinationCIDRs: []string{"10.1.0.0/16", "2001:db8::/32"},
		},
	))
	tests := []struct {
		host string
		port uint16
		want bool
	}{
		{"api.example.com", 443, true},
		{"API.Example.COM", 443, true},
		{"api.example.com", 8443, false},
		{"x.api.example.com", 443, false},
		{"a.svc.example.com", 9000, true},
		{"a.svc.example.com", 9100, true},
		{"a.svc.example.com", 9101, false},
		// Wildcards match exactly one prefix label.
		{"a.b.svc.example.com", 9050, false},
		{"svc.example.com", 9050, false},
		// IP literals match CIDRs, never hostname rules.
		{"10.1.2.3", 80, true},
		{"10.2.0.1", 443, false},
		{"2001:db8::1", 443, true},
		{"::ffff:10.1.2.3", 443, true},
		{"", 443, false},
	}
	for _, tt := range tests {
		if got := m.MatchAuthority(tt.host, tt.port); got != tt.want {
			t.Errorf("MatchAuthority(%q, %d) = %v, want %v", tt.host, tt.port, got, tt.want)
		}
	}
}

func TestDestinationMatcherFailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		match clrkv1alpha1.L4RouteMatch
	}{
		{"sourceAgents can't be evaluated at the proxy", clrkv1alpha1.L4RouteMatch{
			DestinationHostnames: []gwapiv1.Hostname{"api.example.com"},
			SourceAgents:         &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}},
		}},
		{"unparseable CIDR", clrkv1alpha1.L4RouteMatch{
			DestinationHostnames: []gwapiv1.Hostname{"api.example.com"},
			DestinationCIDRs:     []string{"not-a-cidr"},
		}},
		{"half-open port range", clrkv1alpha1.L4RouteMatch{
			DestinationHostnames: []gwapiv1.Hostname{"api.example.com"},
			Ports:                []clrkv1alpha1.L4PortMatch{{StartPort: ptr.To[int32](443)}},
		}},
		{"inverted port range", clrkv1alpha1.L4RouteMatch{
			DestinationHostnames: []gwapiv1.Hostname{"api.example.com"},
			Ports:                []clrkv1alpha1.L4PortMatch{portRangeMatch(8443, 443)},
		}},
		{"out-of-range port", clrkv1alpha1.L4RouteMatch{
			DestinationHostnames: []gwapiv1.Hostname{"api.example.com"},
			Ports:                []clrkv1alpha1.L4PortMatch{port(70000)},
		}},
		{"port and range both set", clrkv1alpha1.L4RouteMatch{
			DestinationHostnames: []gwapiv1.Hostname{"api.example.com"},
			Ports: []clrkv1alpha1.L4PortMatch{{
				Port: ptr.To[int32](443), StartPort: ptr.To[int32](1), EndPort: ptr.To[int32](2),
			}},
		}},
		{"UDP-only block", clrkv1alpha1.L4RouteMatch{
			DestinationHostnames: []gwapiv1.Hostname{"api.example.com"},
			Protocol:             ptr.To(clrkv1alpha1.L4ProtocolUDP),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewDestinationMatcher(l4Route(tt.match))
			if m.MatchAuthority("api.example.com", 443) {
				t.Fatal("matched; want no match")
			}
		})
	}

	usable, dropped := NewDestinationMatcher(l4Route(tests[0].match, tests[1].match,
		clrkv1alpha1.L4RouteMatch{DestinationHostnames: []gwapiv1.Hostname{"ok.example.com"}})).Counts()
	if usable != 1 || dropped != 2 {
		t.Fatalf("Counts() = (%d, %d), want (1, 2)", usable, dropped)
	}
}

func TestDestinationMatcherEmptyBlockMatchesEverything(t *testing.T) {
	// An empty match block is an allow-all on the dial-time allowlist; the
	// credential scope follows the route's own semantics.
	m := NewDestinationMatcher(l4Route(clrkv1alpha1.L4RouteMatch{}))
	if !m.MatchAuthority("anything.example.com", 1234) {
		t.Fatal("empty match block should match every destination")
	}
	// A rule without matches compiles to nothing, as compileRouteTable does.
	if NewDestinationMatcher(l4Route()).MatchAuthority("anything.example.com", 443) {
		t.Fatal("rule without matches should match nothing")
	}
}

func TestRouteAttachesTo(t *testing.T) {
	r := l4Route()
	if !RouteAttachesTo(r, "default", "eg") {
		t.Fatal("same-namespace parentRef should attach")
	}
	if RouteAttachesTo(r, "other", "eg") || RouteAttachesTo(r, "default", "other") {
		t.Fatal("parentRef should not attach to a different EG")
	}
	r.Spec.ParentRefs[0].Namespace = ptr.To(gwapiv1.Namespace("other"))
	if !RouteAttachesTo(r, "other", "eg") {
		t.Fatal("explicit parentRef namespace should attach")
	}
}
