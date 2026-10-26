package v1alpha1

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

func cipWithTarget(group, kind, name string, section *string) *CredentialInjectionPolicy {
	ref := gwapiv1a2.LocalPolicyTargetReferenceWithSectionName{
		LocalPolicyTargetReference: gwapiv1a2.LocalPolicyTargetReference{
			Group: gwapiv1.Group(group),
			Kind:  gwapiv1.Kind(kind),
			Name:  gwapiv1.ObjectName(name),
		},
	}
	if section != nil {
		ref.SectionName = ptr.To(gwapiv1.SectionName(*section))
	}
	return &CredentialInjectionPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "cip"},
		Spec: CredentialInjectionSpec{
			TargetRefs: []gwapiv1a2.LocalPolicyTargetReferenceWithSectionName{ref},
			SecretRef:  gwapiv1.SecretObjectReference{Name: "cred"},
			Target:     CredentialTargetHeader,
			HeaderName: ptr.To("Authorization"),
		},
	}
}

func TestCredentialInjectionPolicyValidateTargets(t *testing.T) {
	group := SchemeGroupVersion.Group
	tests := []struct {
		name    string
		cip     *CredentialInjectionPolicy
		wantErr string // substring of the aggregated error; "" means valid
	}{
		{"EgressL4Route target", cipWithTarget(group, "EgressL4Route", "upstream-a", nil), ""},
		{"EgressGateway target", cipWithTarget(group, "EgressGateway", "eg", nil), ""},
		{"AIProviderRoute backend section", cipWithTarget(group, "AIProviderRoute", "apr", ptr.To("b1")), ""},
		{"EgressL4Route sectionName", cipWithTarget(group, "EgressL4Route", "upstream-a", ptr.To("rule-0")),
			"spec.targetRefs[0].sectionName"},
		{"EgressL4Route without group", cipWithTarget("", "EgressL4Route", "upstream-a", nil),
			"spec.targetRefs[0].group"},
		{"EgressL4Route in another group", cipWithTarget("gateway.networking.k8s.io", "EgressL4Route", "upstream-a", nil),
			"spec.targetRefs[0].group"},
		{"unsupported kind", cipWithTarget(group, "Backend", "b", nil), "spec.targetRefs[0].kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cip.Validate(context.Background())
			if tt.wantErr == "" {
				if len(errs) != 0 {
					t.Fatalf("unexpected errors: %v", errs.ToAggregate())
				}
				return
			}
			if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), tt.wantErr) {
				t.Fatalf("errors %v, want one on %s", errs.ToAggregate(), tt.wantErr)
			}
		})
	}
}
