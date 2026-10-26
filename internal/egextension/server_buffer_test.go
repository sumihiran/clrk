package egextension

import (
	"context"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	clrkv1alpha1 "github.com/apoxy-dev/clrk/api/clrk/v1alpha1"
)

// hcmChain builds a filter chain holding one HCM with a router filter,
// the shape Envoy Gateway hands the extension.
func hcmChain(t *testing.T, h2 *corev3.Http2ProtocolOptions) *listenerv3.FilterChain {
	t.Helper()
	router, err := anypb.New(&routerv3.Router{})
	if err != nil {
		t.Fatal(err)
	}
	hcm, err := anypb.New(&hcmv3.HttpConnectionManager{
		StatPrefix:           "test",
		Http2ProtocolOptions: h2,
		HttpFilters: []*hcmv3.HttpFilter{{
			Name:       routerFilterName,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: router},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &listenerv3.FilterChain{Filters: []*listenerv3.Filter{{
		Name:       hcmFilterName,
		ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: hcm},
	}}}
}

func chainHCM(t *testing.T, fc *listenerv3.FilterChain) *hcmv3.HttpConnectionManager {
	t.Helper()
	hcm := &hcmv3.HttpConnectionManager{}
	if err := fc.GetFilters()[0].GetTypedConfig().UnmarshalTo(hcm); err != nil {
		t.Fatal(err)
	}
	return hcm
}

func TestRewriteHCMRaisesHTTP2Windows(t *testing.T) {
	s := &Server{}
	key := egKey{namespace: "default", name: "eg"}
	cfg := &llmConfig{requestTimeout: clrkv1alpha1.DefaultEgressRequestTimeout}

	tests := []struct {
		name                 string
		in                   *corev3.Http2ProtocolOptions
		bufferLimit          uint32
		wantStream, wantConn uint32
	}{
		{"unset", nil, clrkv1alpha1.DefaultCapturedBodyBufferBytes,
			downstreamH2StreamWindowBytes, downstreamH2ConnectionWindowBytes},
		{"Envoy Gateway defaults", &corev3.Http2ProtocolOptions{
			InitialStreamWindowSize:     wrapperspb.UInt32(64 << 10),
			InitialConnectionWindowSize: wrapperspb.UInt32(1 << 20),
		}, clrkv1alpha1.DefaultCapturedBodyBufferBytes, downstreamH2StreamWindowBytes, downstreamH2ConnectionWindowBytes},
		{"buffer limit above the default window", nil, 48 << 20, 48 << 20, 96 << 20},
		{"larger ClientTrafficPolicy values win", &corev3.Http2ProtocolOptions{
			InitialStreamWindowSize:     wrapperspb.UInt32(64 << 20),
			InitialConnectionWindowSize: wrapperspb.UInt32(256 << 20),
		}, clrkv1alpha1.DefaultCapturedBodyBufferBytes, 64 << 20, 256 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := hcmChain(t, tt.in)
			if err := s.rewriteHCM(fc, key, s.dnsCacheConfigFor(context.Background(), key), cfg, tt.bufferLimit); err != nil {
				t.Fatal(err)
			}
			h2 := chainHCM(t, fc).GetHttp2ProtocolOptions()
			if got := h2.GetInitialStreamWindowSize().GetValue(); got != tt.wantStream {
				t.Errorf("initial_stream_window_size = %d, want %d", got, tt.wantStream)
			}
			if got := h2.GetInitialConnectionWindowSize().GetValue(); got != tt.wantConn {
				t.Errorf("initial_connection_window_size = %d, want %d", got, tt.wantConn)
			}
		})
	}
}

func TestApplyHTTPShapeRaisesConnectionBufferLimit(t *testing.T) {
	s := &Server{}
	key := egKey{namespace: "default", name: "eg"}
	ctx := context.Background()
	cfg := &llmConfig{requestTimeout: clrkv1alpha1.DefaultEgressRequestTimeout}

	for _, tt := range []struct {
		name string
		in   *wrapperspb.UInt32Value
		want uint32
	}{
		{"unset", nil, clrkv1alpha1.DefaultCapturedBodyBufferBytes},
		{"Envoy Gateway default", wrapperspb.UInt32(32 << 10), clrkv1alpha1.DefaultCapturedBodyBufferBytes},
		{"larger ClientTrafficPolicy value wins", wrapperspb.UInt32(64 << 20), 64 << 20},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l := &listenerv3.Listener{
				Name:                          "default/clrk-eg-eg/egress",
				PerConnectionBufferLimitBytes: tt.in,
				FilterChains:                  []*listenerv3.FilterChain{hcmChain(t, nil)},
			}
			s.applyHTTPShape(ctx, l, key, clrkv1alpha1.EgressShapeHTTP, s.dnsCacheConfigFor(ctx, key), cfg)
			if got := l.GetPerConnectionBufferLimitBytes().GetValue(); got != tt.want {
				t.Fatalf("per_connection_buffer_limit_bytes = %d, want %d", got, tt.want)
			}
		})
	}
}
