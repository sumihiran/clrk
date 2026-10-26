package egress

import (
	"net"
	"net/netip"
	"strings"

	clrkv1alpha1 "github.com/apoxy-dev/clrk/api/clrk/v1alpha1"
)

// routeEntry is a single compiled routing rule.
type routeEntry struct {
	// Match criteria.
	cidrs     []netip.Prefix
	hostnames []string // exact ("api.openai.com") or wildcard ("*.openai.com")
	ports     []portRange
	protocol  *clrkv1alpha1.L4Protocol

	// Result to return on match.
	result RouteResult
}

// portRange is an inclusive port range.
type portRange struct {
	start uint16
	end   uint16
}

// routeTable is an immutable, compiled set of routing rules.
type routeTable struct {
	entries []routeEntry
}

// match finds the first matching route for the given destination,
// protocol, and DNS-bound destination name. dstName is the hostname
// the agent's resolver answered for dst.Addr (see DNSCache); empty
// when nothing was bound (direct-IP dial, DNS bypass, or expired
// entry), in which case hostname-only rules cannot match.
// Returns nil if no route matches.
func (t *routeTable) match(dst netip.AddrPort, proto clrkv1alpha1.L4Protocol, dstName string) *RouteResult {
	for i := range t.entries {
		if t.entries[i].matches(dst, proto, dstName) {
			r := t.entries[i].result
			return &r
		}
	}
	return nil
}

// matches checks whether the given destination, protocol, and bound
// DNS name match this entry. CIDR and hostname criteria are OR'd
// within a single match block: either CIDR or hostname is enough.
func (e *routeEntry) matches(dst netip.AddrPort, proto clrkv1alpha1.L4Protocol, dstName string) bool {
	// Protocol filter.
	if e.protocol != nil && *e.protocol != proto {
		return false
	}

	// Either CIDR or hostname must match within the block.
	if len(e.cidrs) > 0 || len(e.hostnames) > 0 {
		dstMatch := false
		for _, cidr := range e.cidrs {
			if cidr.Contains(dst.Addr()) {
				dstMatch = true
				break
			}
		}
		if !dstMatch && dstName != "" {
			for _, h := range e.hostnames {
				if hostnameMatches(h, dstName) {
					dstMatch = true
					break
				}
			}
		}
		if !dstMatch {
			return false
		}
	}

	// Port filter.
	if len(e.ports) > 0 {
		matched := false
		port := dst.Port()
		for _, pr := range e.ports {
			if port >= pr.start && port <= pr.end {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// hostnameMatches reports whether candidate satisfies the rule.
// Exact form ("api.openai.com") requires equality; leading-star
// wildcard ("*.openai.com") matches exactly one extra label per
// RFC 4592 / gwapiv1.Hostname — `*.openai.com` matches
// `api.openai.com` but not `openai.com` and not `foo.bar.openai.com`.
func hostnameMatches(rule, candidate string) bool {
	if strings.HasPrefix(rule, "*.") {
		suffix := rule[1:]
		if !strings.HasSuffix(candidate, suffix) {
			return false
		}
		return strings.Count(candidate, ".") == strings.Count(rule, ".")
	}
	return rule == candidate
}

// routesForEG returns the EgressL4Routes whose ParentRefs target the
// given EG. A route's ParentRef.Namespace defaults to the route's own
// namespace (gwapiv1 semantics).
func routesForEG(routes []clrkv1alpha1.EgressL4Route, egNamespace, egName string) []clrkv1alpha1.EgressL4Route {
	var out []clrkv1alpha1.EgressL4Route
	for _, r := range routes {
		if RouteAttachesTo(r, egNamespace, egName) {
			out = append(out, r)
		}
	}
	return out
}

// RouteAttachesTo reports whether any of the route's ParentRefs targets
// the given EG — the attachment rule the dial-time allowlist applies.
// Exported so the ext_proc credential table scopes EgressL4Route-targeted
// CredentialInjectionPolicies with exactly the same rule.
func RouteAttachesTo(route clrkv1alpha1.EgressL4Route, egNamespace, egName string) bool {
	for _, ref := range route.Spec.ParentRefs {
		if string(ref.Name) != egName {
			continue
		}
		ns := route.Namespace
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}
		if ns == egNamespace {
			return true
		}
	}
	return false
}

// DestinationMatcher answers whether an L7 request's destination — the
// host:port the forward proxy actually dials — falls under one of an
// EgressL4Route's rule matches. It reuses routeEntry, so hostname
// (gwapiv1.Hostname, one-label wildcard), CIDR and port semantics are the
// ones the dial-time allowlist applies.
//
// Unlike compileRouteTable, compilation is strict: a match block with a
// criterion that can't be honored at L7 (sourceAgents, which the proxy
// can't evaluate) or that doesn't parse (a bad CIDR, a half-open port
// range) is dropped instead of silently widening. The matcher gates
// credential injection, so every doubt resolves to "no match".
type DestinationMatcher struct {
	entries []routeEntry
	// dropped counts match blocks compileStrictMatch rejected.
	dropped int
}

// NewDestinationMatcher compiles every rule match of route.
func NewDestinationMatcher(route clrkv1alpha1.EgressL4Route) *DestinationMatcher {
	m := &DestinationMatcher{}
	for _, rule := range route.Spec.Rules {
		for i := range rule.Matches {
			if e, ok := compileStrictMatch(&rule.Matches[i]); ok {
				m.entries = append(m.entries, e)
			} else {
				m.dropped++
			}
		}
	}
	return m
}

// Counts returns how many of the route's match blocks were compiled and
// how many were dropped as not honorable at L7. Status reporting uses it
// to flag a policy whose route can never match.
func (m *DestinationMatcher) Counts() (usable, dropped int) {
	return len(m.entries), m.dropped
}

// MatchAuthority reports whether host:port matches any compiled match
// block. host is the authority's host part without brackets: a DNS name
// is matched against destinationHostnames (case-insensitively, DNS names
// are), an IP literal against destinationCIDRs. HTTP traffic is TCP, so a
// block restricted to UDP never matches.
func (m *DestinationMatcher) MatchAuthority(host string, port uint16) bool {
	if m == nil || host == "" {
		return false
	}
	var (
		dst     netip.AddrPort
		dstName string
	)
	if addr, err := netip.ParseAddr(host); err == nil {
		dst = netip.AddrPortFrom(addr.Unmap(), port)
	} else {
		// The zero Addr is contained in no prefix, so only hostname
		// rules can match a DNS name.
		dst = netip.AddrPortFrom(netip.Addr{}, port)
		dstName = strings.ToLower(host)
	}
	for i := range m.entries {
		if m.entries[i].matches(dst, clrkv1alpha1.L4ProtocolTCP, dstName) {
			return true
		}
	}
	return false
}

// compileStrictMatch compiles one match block for DestinationMatcher,
// returning ok=false when any criterion can't be honored as written.
func compileStrictMatch(m *clrkv1alpha1.L4RouteMatch) (routeEntry, bool) {
	var e routeEntry
	if m.SourceAgents != nil {
		return e, false
	}
	for _, cidrStr := range m.DestinationCIDRs {
		prefix, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			return e, false
		}
		e.cidrs = append(e.cidrs, netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()))
	}
	for _, h := range m.DestinationHostnames {
		e.hostnames = append(e.hostnames, strings.ToLower(string(h)))
	}
	for _, pm := range m.Ports {
		pr, ok := strictPortRange(pm)
		if !ok {
			return e, false
		}
		e.ports = append(e.ports, pr)
	}
	e.protocol = m.Protocol
	return e, true
}

// strictPortRange converts a port match, rejecting anything other than
// exactly one of a valid single port or a valid ordered range.
func strictPortRange(pm clrkv1alpha1.L4PortMatch) (portRange, bool) {
	valid := func(p int32) bool { return p >= 1 && p <= 65535 }
	switch {
	case pm.Port != nil && pm.StartPort == nil && pm.EndPort == nil:
		if !valid(*pm.Port) {
			return portRange{}, false
		}
		return portRange{start: uint16(*pm.Port), end: uint16(*pm.Port)}, true
	case pm.Port == nil && pm.StartPort != nil && pm.EndPort != nil:
		if !valid(*pm.StartPort) || !valid(*pm.EndPort) || *pm.StartPort > *pm.EndPort {
			return portRange{}, false
		}
		return portRange{start: uint16(*pm.StartPort), end: uint16(*pm.EndPort)}, true
	}
	return portRange{}, false
}

// compileRouteTable builds a routeTable from CRD objects.
func compileRouteTable(
	_ []clrkv1alpha1.EgressGateway,
	l4Routes []clrkv1alpha1.EgressL4Route,
) *routeTable {
	var entries []routeEntry

	for _, route := range l4Routes {
		for _, rule := range route.Spec.Rules {
			for _, m := range rule.Matches {
				entry := routeEntry{
					result: RouteResult{Action: ActionPassthrough},
				}

				// Parse CIDRs.
				for _, cidrStr := range m.DestinationCIDRs {
					_, ipNet, err := net.ParseCIDR(cidrStr)
					if err != nil {
						continue
					}
					prefix, ok := netip.AddrFromSlice(ipNet.IP)
					if !ok {
						continue
					}
					ones, _ := ipNet.Mask.Size()
					entry.cidrs = append(entry.cidrs, netip.PrefixFrom(prefix.Unmap(), ones))
				}

				// Hostnames — exact + leading-wildcard, matched against
				// the DNS-bound destination name on TCP connect (see
				// DNSCache). On TLS listeners SNI matching takes over;
				// see internal/egextension for that path.
				for _, h := range m.DestinationHostnames {
					entry.hostnames = append(entry.hostnames, string(h))
				}

				// Parse ports.
				for _, pm := range m.Ports {
					if pm.Port != nil {
						p := uint16(*pm.Port)
						entry.ports = append(entry.ports, portRange{start: p, end: p})
					} else if pm.StartPort != nil && pm.EndPort != nil {
						entry.ports = append(entry.ports, portRange{
							start: uint16(*pm.StartPort),
							end:   uint16(*pm.EndPort),
						})
					}
				}

				// Protocol.
				if m.Protocol != nil {
					entry.protocol = m.Protocol
				}

				// Backend refs.
				if len(rule.BackendRefs) > 0 {
					entry.result.Action = ActionBackendRef
					// Use the first backend ref for now.
					ref := rule.BackendRefs[0]
					entry.result.BackendAddr = string(ref.Name)
				}

				entries = append(entries, entry)
			}
		}
	}

	return &routeTable{entries: entries}
}
