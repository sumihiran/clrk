package extproc

import (
	"testing"
	"time"

	extprocfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"

	"github.com/apoxy-dev/clrk/internal/extproc/capture"
)

// TestResponseBodyModeOverride pins the response-headers decision: a body
// whose content type isn't captured streams through (NONE), everything
// that is captured, streamed or translated keeps today's mode.
func TestResponseBodyModeOverride(t *testing.T) {
	none := modeOverride(extprocfilterv3.ProcessingMode_NONE, extprocfilterv3.ProcessingMode_NONE)
	streamed := modeOverride(extprocfilterv3.ProcessingMode_NONE, extprocfilterv3.ProcessingMode_STREAMED)

	tests := []struct {
		name            string
		contentType     string
		status          string
		eos             bool
		streamRequested bool
		included        []string
		translated      bool
		want            *extprocfilterv3.ProcessingMode // nil: static BUFFERED default
		wantSkipped     bool
	}{
		{name: "uncaptured download streams through", contentType: "application/octet-stream", status: "200",
			want: none, wantSkipped: true},
		{name: "uncaptured error body streams through", contentType: "text/html; charset=utf-8", status: "404",
			want: none, wantSkipped: true},
		{name: "missing content type is not captured", status: "200", want: none, wantSkipped: true},
		{name: "captured JSON stays buffered", contentType: "application/json", status: "200"},
		{name: "captured JSON error stays buffered", contentType: "application/json", status: "500"},
		{name: "operator-captured type stays buffered", contentType: "application/octet-stream", status: "200",
			included: []string{"application/octet-stream"}},
		{name: "SSE is promoted to STREAMED", contentType: "text/event-stream", status: "200", want: streamed},
		{name: "SSE outside the capture list is still promoted", contentType: "text/event-stream", status: "200",
			included: []string{"application/json"}, want: streamed},
		{name: "non-200 SSE outside the capture list stays buffered", contentType: "text/event-stream", status: "429",
			included: []string{"application/json"}},
		{name: "requested stream keeps STREAMED for token accounting", contentType: "application/octet-stream",
			status: "200", streamRequested: true, want: streamed},
		{name: "bodyless response needs no override", contentType: "application/octet-stream", status: "200", eos: true},
		{name: "translated response is never skipped", contentType: "application/octet-stream", status: "200",
			translated: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := newTestDownstream(nil)
			ds.includedTypes = tt.included
			if ds.includedTypes == nil {
				ds.includedTypes = capture.DefaultIncludedContentTypes
			}
			ds.streamRequested = tt.streamRequested
			if tt.translated {
				ds.xlate = &translationState{}
			}
			kv := []string{":status", tt.status}
			if tt.contentType != "" {
				kv = append(kv, "content-type", tt.contentType)
			}
			hdrs := requestHeaders(kv...)
			hdrs.EndOfStream = tt.eos
			resp := ds.onResponseHeaders(hdrs, time.Now())
			got := resp.GetModeOverride()
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("ModeOverride = %v, want none (static BUFFERED)", got)
			case tt.want != nil && (got == nil ||
				got.GetRequestBodyMode() != tt.want.GetRequestBodyMode() ||
				got.GetResponseBodyMode() != tt.want.GetResponseBodyMode()):
				t.Fatalf("ModeOverride = %v, want %v", got, tt.want)
			}
			if ds.rec.ResponseBodySkipped != tt.wantSkipped {
				t.Fatalf("ResponseBodySkipped = %v, want %v", ds.rec.ResponseBodySkipped, tt.wantSkipped)
			}
		})
	}
}
