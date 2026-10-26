package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	clrkv1alpha1 "github.com/apoxy-dev/clrk/api/clrk/v1alpha1"
)

// TestCatchAllRouteCarriesBufferRevision checks that a captureBody.maxBytes
// edit which moves the listener buffer limit perturbs the catch-all
// HTTPRoute — the only thing that makes Envoy Gateway re-run the extension
// hook that sets the limit.
func TestCatchAllRouteCarriesBufferRevision(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clrkv1alpha1.AddToScheme, gwapiv1.Install} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	bufferRev := func(maxBytes *int32) string {
		eg := &clrkv1alpha1.EgressGateway{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "eg", UID: "uid"},
			Spec: clrkv1alpha1.EgressGatewaySpec{
				OTLP: &clrkv1alpha1.OTLPLogsSinkSpec{CaptureBody: &clrkv1alpha1.BodyCaptureSpec{MaxBytes: maxBytes}},
			},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(eg).Build()
		r := &EgressGatewayReconciler{Client: c, Scheme: scheme}
		if err := r.ensureCatchAllRoute(context.Background(), eg, ""); err != nil {
			t.Fatal(err)
		}
		var rt gwapiv1.HTTPRoute
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: GatewayNamePrefix + "eg-catchall"}, &rt); err != nil {
			t.Fatal(err)
		}
		for _, rule := range rt.Spec.Rules {
			for _, m := range rule.Matches {
				for _, h := range m.Headers {
					if string(h.Name) == BufferRevHeaderName {
						return h.Value
					}
				}
			}
		}
		return ""
	}
	if got := bufferRev(ptr.To[int32](64 << 10)); got != "" {
		t.Fatalf("default limit carries a buffer revision %q", got)
	}
	if got := bufferRev(ptr.To[int32](16 << 20)); got != "16777216" {
		t.Fatalf("buffer revision = %q, want 16777216", got)
	}
}
