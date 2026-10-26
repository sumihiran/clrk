package controller

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	clrkv1alpha1 "github.com/apoxy-dev/clrk/api/clrk/v1alpha1"
)

func TestCredentialInjectionPolicyStatusEgressL4RouteTarget(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clrkv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	route := func(name string, m clrkv1alpha1.L4RouteMatch) *clrkv1alpha1.EgressL4Route {
		return &clrkv1alpha1.EgressL4Route{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
			Spec: clrkv1alpha1.EgressL4RouteSpec{
				ParentRefs: []gwapiv1.ParentReference{{Name: "eg"}},
				Rules:      []clrkv1alpha1.EgressL4RouteRule{{Matches: []clrkv1alpha1.L4RouteMatch{m}}},
			},
		}
	}
	hostMatch := clrkv1alpha1.L4RouteMatch{DestinationHostnames: []gwapiv1.Hostname{"api.example.com"}}
	agentMatch := hostMatch
	agentMatch.SourceAgents = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}

	tests := []struct {
		name       string
		target     string
		wantStatus metav1.ConditionStatus
		wantReason gwapiv1a2.PolicyConditionReason
		wantMsg    string
	}{
		{"usable route", "usable", metav1.ConditionTrue, gwapiv1a2.PolicyReasonAccepted, "Attached to EgressL4Route"},
		{"route with only sourceAgents matches", "agents-only", metav1.ConditionFalse, gwapiv1a2.PolicyReasonInvalid, "never injected"},
		{"missing route", "missing", metav1.ConditionFalse, gwapiv1a2.PolicyReasonTargetNotFound, "not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cip := &clrkv1alpha1.CredentialInjectionPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cip", Generation: 1},
				Spec: clrkv1alpha1.CredentialInjectionSpec{
					TargetRefs: []gwapiv1a2.LocalPolicyTargetReferenceWithSectionName{{
						LocalPolicyTargetReference: gwapiv1a2.LocalPolicyTargetReference{
							Group: routeStatusGroup, Kind: "EgressL4Route", Name: gwapiv1.ObjectName(tt.target),
						},
					}},
					SecretRef:  gwapiv1.SecretObjectReference{Name: "cred"},
					Target:     clrkv1alpha1.CredentialTargetHeader,
					HeaderName: ptr.To("Authorization"),
				},
			}
			c := fake.NewClientBuilder().WithScheme(scheme).
				WithStatusSubresource(&clrkv1alpha1.CredentialInjectionPolicy{}).
				WithObjects(cip, route("usable", hostMatch), route("agents-only", agentMatch)).
				Build()
			r := &CredentialInjectionPolicyStatusReconciler{Client: c, Scheme: scheme}
			key := types.NamespacedName{Namespace: "default", Name: "cip"}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
				t.Fatal(err)
			}
			var got clrkv1alpha1.CredentialInjectionPolicy
			if err := c.Get(context.Background(), key, &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Status.Ancestors) != 1 {
				t.Fatalf("ancestors = %d, want 1", len(got.Status.Ancestors))
			}
			cond := meta.FindStatusCondition(got.Status.Ancestors[0].Conditions, string(gwapiv1a2.PolicyConditionAccepted))
			if cond == nil {
				t.Fatal("no Accepted condition")
			}
			if cond.Status != tt.wantStatus || cond.Reason != string(tt.wantReason) || !strings.Contains(cond.Message, tt.wantMsg) {
				t.Fatalf("Accepted = %s/%s %q, want %s/%s containing %q",
					cond.Status, cond.Reason, cond.Message, tt.wantStatus, tt.wantReason, tt.wantMsg)
			}
		})
	}
}
