// Command otlpsink is a throwaway OTLP/HTTP trace receiver. It decodes
// ExportTraceServiceRequest protobufs posted to /v1/traces and prints one line
// per span (name, trace id, selected attributes) so the spike can show that
// agentgateway exports traces and which attributes they carry.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"
)

func attrVal(v *commonpb.AnyValue) string {
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return fmt.Sprint(x.IntValue)
	case *commonpb.AnyValue_BoolValue:
		return fmt.Sprint(x.BoolValue)
	case *commonpb.AnyValue_DoubleValue:
		return fmt.Sprint(x.DoubleValue)
	default:
		return v.String()
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:4318", "listen address")
	flag.Parse()
	http.HandleFunc("/v1/traces", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req coltrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(b, &req); err != nil {
			fmt.Printf("{\"otlp_decode_error\":%q,\"content_type\":%q}\n", err.Error(), r.Header.Get("Content-Type"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, rs := range req.GetResourceSpans() {
			svc := ""
			for _, a := range rs.GetResource().GetAttributes() {
				if a.GetKey() == "service.name" {
					svc = attrVal(a.GetValue())
				}
			}
			for _, ss := range rs.GetScopeSpans() {
				for _, sp := range ss.GetSpans() {
					attrs := map[string]string{}
					for _, a := range sp.GetAttributes() {
						k := a.GetKey()
						if strings.HasPrefix(k, "mcp.") || strings.HasPrefix(k, "fortik") || strings.HasPrefix(k, "gen_ai") ||
							strings.HasPrefix(k, "http.") || strings.HasPrefix(k, "rpc.") || strings.Contains(k, "status") || strings.HasPrefix(k, "url.") {
							attrs[k] = attrVal(a.GetValue())
						}
					}
					line, _ := json.Marshal(map[string]any{
						"service": svc, "span": sp.GetName(), "trace_id": hex.EncodeToString(sp.GetTraceId()),
						"parent": hex.EncodeToString(sp.GetParentSpanId()), "attrs": attrs,
					})
					fmt.Println(string(line))
				}
			}
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		out, _ := proto.Marshal(&coltrace.ExportTraceServiceResponse{})
		_, _ = w.Write(out)
	})
	fmt.Fprintf(os.Stderr, "otlpsink listening on http://%s/v1/traces\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
