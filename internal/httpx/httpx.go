// Package httpx holds the JSON conventions shared by every Fortik HTTP
// surface (API, gateway): strict decoding, JSON responses, error shape
// {"error": "..."} (or a structured object for gateway refusals).
package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// MaxBody is the default request body limit for API JSON bodies.
const MaxBody = 1 << 20

// DecodeStrict decodes one JSON value, rejecting unknown fields, trailing
// data and bodies over limit bytes (limit <= 0 means MaxBody).
func DecodeStrict(r *http.Request, v any, limit int64) error {
	if limit <= 0 {
		limit = MaxBody
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, limit+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if dec.More() {
		return errors.New("invalid JSON body: trailing data")
	}
	return nil
}

func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func WriteError(w http.ResponseWriter, code int, msg string) {
	WriteJSON(w, code, map[string]string{"error": msg})
}
