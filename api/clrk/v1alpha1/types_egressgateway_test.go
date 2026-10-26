package v1alpha1

import (
	"testing"

	"k8s.io/utils/ptr"
)

func TestEffectiveCapturedBodyBufferBytes(t *testing.T) {
	spec := func(maxBytes *int32) *EgressGatewaySpec {
		return &EgressGatewaySpec{OTLP: &OTLPLogsSinkSpec{CaptureBody: &BodyCaptureSpec{MaxBytes: maxBytes}}}
	}
	tests := []struct {
		name string
		spec *EgressGatewaySpec
		want uint32
	}{
		{"no OTLP spec", &EgressGatewaySpec{}, DefaultCapturedBodyBufferBytes},
		{"no maxBytes", spec(nil), DefaultCapturedBodyBufferBytes},
		{"maxBytes below the floor", spec(ptr.To[int32](64 << 10)), DefaultCapturedBodyBufferBytes},
		{"maxBytes above the floor", spec(ptr.To[int32](16 << 20)), 16 << 20},
		{"maxBytes above the cap", spec(ptr.To[int32](1 << 30)), MaxCapturedBodyBufferBytes},
	}
	for _, tt := range tests {
		if got := tt.spec.EffectiveCapturedBodyBufferBytes(); got != tt.want {
			t.Errorf("%s: got %d, want %d", tt.name, got, tt.want)
		}
	}
}
