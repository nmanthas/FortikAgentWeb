package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyStripsCredentialsAndHopByHop(t *testing.T) {
	var got http.Header
	var gotBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Set-Cookie", "session=upstream")
		w.Header().Set("Connection", "X-Private")
		w.Header().Set("X-Private", "hop")
		w.Header().Set("X-Fortik-Action-Id", "spoofed")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"id":"1"}`)
	}))
	defer up.Close()

	in := http.Header{}
	in.Set("Authorization", "Bearer agt_agent_token")
	in.Set("Cookie", "a=b")
	in.Set("X-Fortik-Instance-Id", "i1")
	in.Set("X-Forwarded-For", "1.2.3.4")
	in.Set("Accept", "application/json")
	in.Set("Content-Type", "text/plain")
	in.Set("X-Goog-User-Project", "other")
	w := httptest.NewRecorder()
	res, err := Proxy(context.Background(), w, ProxyRequest{Method: "POST", URL: up.URL + "/x", Body: []byte("hello"),
		Header: in, Authorization: "Bearer fortik-held", Capture: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Get("Authorization") != "Bearer fortik-held" {
		t.Fatalf("upstream Authorization = %q", got.Get("Authorization"))
	}
	for _, h := range []string{"Cookie", "X-Fortik-Instance-Id", "X-Forwarded-For", "X-Goog-User-Project"} {
		if got.Get(h) != "" {
			t.Errorf("%s forwarded upstream", h)
		}
	}
	if got.Get("Accept") != "application/json" || got.Get("Content-Type") != "text/plain" || gotBody != "hello" {
		t.Fatalf("allowed headers/body not forwarded: %v %q", got, gotBody)
	}
	if w.Code != 201 || w.Body.String() != `{"id":"1"}` || string(res.Body) != `{"id":"1"}` || res.Status != 201 {
		t.Fatalf("response: %d %q %+v", w.Code, w.Body, res)
	}
	for _, h := range []string{"Set-Cookie", "Connection", "X-Private", "X-Fortik-Action-Id"} {
		if w.Header().Get(h) != "" {
			t.Errorf("%s echoed to the agent", h)
		}
	}
}

func TestProxyTransportErrorWritesNothing(t *testing.T) {
	up := httptest.NewServer(http.NotFoundHandler())
	u := up.URL
	up.Close()
	w := httptest.NewRecorder()
	_, err := Proxy(context.Background(), w, ProxyRequest{Method: "GET", URL: u})
	if !errors.Is(err, ErrUpstream) {
		t.Fatalf("err = %v", err)
	}
	if w.Body.Len() != 0 || len(w.Header()) != 0 {
		t.Fatal("wrote a response on transport error")
	}
}
