package extproc

import (
	"bytes"
	"context"
	"io"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	netextprocsvcv3 "github.com/envoyproxy/go-control-plane/envoy/service/network_ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

// fakeL4Stream feeds a fixed request sequence to NetworkServer.Process
// and records what it sends back.
type fakeL4Stream struct {
	grpc.ServerStream
	reqs []*netextprocsvcv3.ProcessingRequest
	sent []*netextprocsvcv3.ProcessingResponse
}

func (f *fakeL4Stream) Context() context.Context { return context.Background() }

func (f *fakeL4Stream) Recv() (*netextprocsvcv3.ProcessingRequest, error) {
	if len(f.reqs) == 0 {
		return nil, io.EOF
	}
	r := f.reqs[0]
	f.reqs = f.reqs[1:]
	return r, nil
}

func (f *fakeL4Stream) Send(r *netextprocsvcv3.ProcessingResponse) error {
	f.sent = append(f.sent, r)
	return nil
}

type l4CaptureSink struct{ l4 []L4Record }

func (s *l4CaptureSink) Emit(Record)        {}
func (s *l4CaptureSink) EmitL4(r L4Record) { s.l4 = append(s.l4, r) }

// TestNetworkProcessForwardsReadData pins the fix for stalled
// TLS-passthrough and TCP listeners: every chunk must come back in the
// response, because the filter has already drained it from the
// connection and forwards only what the response carries.
func TestNetworkProcessForwardsReadData(t *testing.T) {
	hello := []byte("\x16\x03\x01client-hello")
	stream := &fakeL4Stream{reqs: []*netextprocsvcv3.ProcessingRequest{
		{
			ReadData: &netextprocsvcv3.Data{Data: hello},
			Metadata: &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
				MetadataNamespace: {Fields: map[string]*structpb.Value{
					MetaAgentName: structpb.NewStringValue("curl"),
					MetaDstName:   structpb.NewStringValue("api.example.com"),
				}},
			}},
		},
		{ReadData: &netextprocsvcv3.Data{Data: []byte("more")}},
		{ReadData: &netextprocsvcv3.Data{EndOfStream: true}},
		{WriteData: &netextprocsvcv3.Data{Data: []byte("server-bytes")}},
	}}
	sink := &l4CaptureSink{}
	srv := New(nil, WithSinkOverride(sink))
	if err := NewNetworkServer(srv).Process(stream); err != nil {
		t.Fatal(err)
	}

	if len(stream.sent) != 4 {
		t.Fatalf("sent %d responses, want one per request (4)", len(stream.sent))
	}
	wantRead := []struct {
		data []byte
		eos  bool
	}{{hello, false}, {[]byte("more"), false}, {nil, true}}
	for i, w := range wantRead {
		r := stream.sent[i]
		if r.GetReadData() == nil {
			t.Fatalf("response %d carries no read_data; Envoy would drop the chunk", i)
		}
		if !bytes.Equal(r.GetReadData().GetData(), w.data) || r.GetReadData().GetEndOfStream() != w.eos {
			t.Fatalf("response %d read_data = %q eos=%v, want %q eos=%v", i,
				r.GetReadData().GetData(), r.GetReadData().GetEndOfStream(), w.data, w.eos)
		}
		if r.GetConnectionStatus() != netextprocsvcv3.ProcessingResponse_CONTINUE {
			t.Fatalf("response %d connection status = %v, want CONTINUE", i, r.GetConnectionStatus())
		}
	}
	if w := stream.sent[3].GetWriteData(); w == nil || string(w.GetData()) != "server-bytes" || stream.sent[3].GetReadData() != nil {
		t.Fatalf("write_data response = %v, want the server bytes echoed in write_data", stream.sent[3])
	}

	if len(sink.l4) != 1 {
		t.Fatalf("emitted %d L4 records, want 1", len(sink.l4))
	}
	rec := sink.l4[0]
	if rec.BytesUpstream != int64(len(hello)+len("more")) || rec.AgentName != "curl" || rec.DstName != "api.example.com" {
		t.Fatalf("record = %+v", rec)
	}
}
