package google

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"sort"
	"strings"
)

// Limits on what the classifier will walk. Anything beyond them is refused
// (mapped to UNKNOWN), never partially classified.
const (
	maxMIMEDepth      = 8
	maxMIMEParts      = 500
	maxTargetAddrs    = 500 // addresses listed in the Action target (counts stay exact)
	maxUploadMetaJSON = 1 << 20
)

var (
	errMalformed   = errors.New("malformed request body")
	errTooComplex  = errors.New("message structure too complex to classify")
	errUnknownKeys = errors.New("request body has fields Fortik does not classify")
)

// normKey folds a JSON field name the way Google's JSON parser matches proto
// fields (lowerCamel and snake_case are both accepted), so two spellings of
// one field are treated as the same field.
func normKey(k string) string {
	return strings.ToLower(strings.ReplaceAll(k, "_", ""))
}

// object parses a JSON object keyed by normKey. Duplicate fields (including
// different spellings of the same field) are rejected: Fortik must never
// classify one value while Google acts on another.
func object(b []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errMalformed
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, errMalformed
		}
		k, ok := kt.(string)
		if !ok {
			return nil, errMalformed
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errMalformed
		}
		nk := normKey(k)
		if _, dup := out[nk]; dup {
			return nil, fmt.Errorf("%w: duplicate field %q", errMalformed, k)
		}
		out[nk] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, errMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", errMalformed)
	}
	return out, nil
}

// onlyKeys rejects any field outside allowed (normalised names).
func onlyKeys(m map[string]json.RawMessage, allowed ...string) error {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range m {
		if !ok[k] {
			return fmt.Errorf("%w: %q", errUnknownKeys, k)
		}
	}
	return nil
}

// jsonString reads an optional string field; a present non-string is an error.
func jsonString(m map[string]json.RawMessage, k string) (string, bool, error) {
	v, ok := m[k]
	if !ok || string(v) == "null" {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false, fmt.Errorf("%w: field %s must be a string", errMalformed, k)
	}
	return s, true, nil
}

// jsonBool reads an optional boolean field; a present non-boolean is an error.
func jsonBool(m map[string]json.RawMessage, k string) (bool, bool, error) {
	v, ok := m[k]
	if !ok || string(v) == "null" {
		return false, false, nil
	}
	var b bool
	if err := json.Unmarshal(v, &b); err != nil {
		return false, false, fmt.Errorf("%w: field %s must be a boolean", errMalformed, k)
	}
	return b, true, nil
}

// decodeRaw decodes Gmail's base64url "raw" field (padding optional; the
// standard alphabet is accepted too). Fortik re-encodes what it decoded when
// sending, so Google receives exactly the bytes that were classified.
func decodeRaw(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if s == "" {
		return nil, fmt.Errorf("%w: empty raw message", errMalformed)
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("%w: raw is not base64url", errMalformed)
}

// message is the classification summary of an RFC 822 message. It keeps the
// raw bytes only so they can be sent (or encrypted for a delayed send); they
// are never logged or written to the Diary.
type message struct {
	raw             []byte
	to, cc, bcc     []string // lower-cased addr-specs, de-duplicated per header
	attachments     int
	attachmentBytes int64
}

// recipients returns every distinct recipient address.
func (m *message) recipients() []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{m.to, m.cc, m.bcc} {
		for _, a := range l {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// domains returns the distinct recipient domains, sorted.
func (m *message) domains() []string {
	seen := map[string]bool{}
	for _, a := range m.recipients() {
		seen[domainOf(a)] = true
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func domainOf(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return ""
	}
	return normDomain(addr[i+1:])
}

// addressParser ignores display-name charsets: only the addr-spec matters,
// and an exotic charset must not make a valid message unclassifiable.
var addressParser = &mail.AddressParser{WordDecoder: &mime.WordDecoder{
	CharsetReader: func(_ string, input io.Reader) (io.Reader, error) { return input, nil },
}}

// parseMessage extracts recipients (every To/Cc/Bcc header, as Gmail uses
// them all) and attachment counts. Any parse failure is an error: the caller
// fails closed.
func parseMessage(raw []byte) (*message, error) {
	msg, err := mail.ReadMessage(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: RFC 822 header: %v", errMalformed, err)
	}
	m := &message{raw: raw}
	for _, f := range []struct {
		name string
		dst  *[]string
	}{{"To", &m.to}, {"Cc", &m.cc}, {"Bcc", &m.bcc}} {
		seen := map[string]bool{}
		for _, v := range msg.Header[f.name] {
			if strings.TrimSpace(v) == "" {
				continue
			}
			list, err := addressParser.ParseList(v)
			if err != nil {
				return nil, fmt.Errorf("%w: %s header: %v", errMalformed, f.name, err)
			}
			for _, a := range list {
				addr := strings.ToLower(strings.TrimSpace(a.Address))
				if addr == "" || domainOf(addr) == "" {
					return nil, fmt.Errorf("%w: %s header has an address without a domain", errMalformed, f.name)
				}
				if !seen[addr] {
					seen[addr] = true
					*f.dst = append(*f.dst, addr)
				}
			}
		}
	}
	h := textproto.MIMEHeader(msg.Header)
	parts := 0
	if err := m.walk(h.Get("Content-Type"), h.Get("Content-Disposition"), h.Get("Content-Transfer-Encoding"), msg.Body, 0, &parts); err != nil {
		return nil, err
	}
	return m, nil
}

// walk counts attachments in a MIME tree.
func (m *message) walk(ct, disp, cte string, body io.Reader, depth int, parts *int) error {
	if depth > maxMIMEDepth {
		return errTooComplex
	}
	mediaType, params, err := mime.ParseMediaType(ct)
	if ct == "" || err != nil {
		mediaType, params = "text/plain", map[string]string{}
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return fmt.Errorf("%w: multipart without boundary", errMalformed)
		}
		mr := multipart.NewReader(body, boundary)
		for {
			p, err := mr.NextRawPart()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return fmt.Errorf("%w: MIME part: %v", errMalformed, err)
			}
			*parts++
			if *parts > maxMIMEParts {
				return errTooComplex
			}
			if err := m.walk(p.Header.Get("Content-Type"), p.Header.Get("Content-Disposition"),
				p.Header.Get("Content-Transfer-Encoding"), p, depth+1, parts); err != nil {
				return err
			}
		}
	}
	attachment := params["name"] != "" || mediaType == "message/rfc822"
	if disp != "" {
		dt, dp, err := mime.ParseMediaType(disp)
		if err != nil {
			attachment = attachment || strings.HasPrefix(strings.ToLower(strings.TrimSpace(disp)), "attachment")
		} else if dt == "attachment" || dp["filename"] != "" {
			attachment = true
		}
	}
	cr := &countingReader{base64: strings.EqualFold(strings.TrimSpace(cte), "base64")}
	if _, err := io.Copy(cr, body); err != nil {
		return fmt.Errorf("%w: MIME body: %v", errMalformed, err)
	}
	if attachment {
		m.attachments++
		m.attachmentBytes += cr.decodedSize()
	}
	return nil
}

// countingReader measures a part body (decoded size for base64).
type countingReader struct {
	base64 bool
	n      int64 // raw bytes, or base64 alphabet characters when base64
}

func (c *countingReader) Write(p []byte) (int, error) {
	if !c.base64 {
		c.n += int64(len(p))
		return len(p), nil
	}
	for _, b := range p {
		if b != '\r' && b != '\n' && b != ' ' && b != '\t' && b != '=' {
			c.n++
		}
	}
	return len(p), nil
}

func (c *countingReader) decodedSize() int64 {
	if c.base64 {
		return c.n * 3 / 4
	}
	return c.n
}

// relatedParts splits a multipart/related upload body into its parts (at
// most two: JSON metadata, then media), as Google's multipart upload expects.
type relatedPart struct {
	contentType string
	body        []byte
}

func parseRelated(contentType string, body []byte) ([]relatedPart, error) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil || mt != "multipart/related" || params["boundary"] == "" {
		return nil, fmt.Errorf("%w: multipart upload must be multipart/related with a boundary", errMalformed)
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var out []relatedPart
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: multipart upload: %v", errMalformed, err)
		}
		if len(out) == 2 {
			return nil, fmt.Errorf("%w: multipart upload has more than two parts", errMalformed)
		}
		if enc := strings.TrimSpace(p.Header.Get("Content-Transfer-Encoding")); enc != "" && !strings.EqualFold(enc, "binary") &&
			!strings.EqualFold(enc, "8bit") && !strings.EqualFold(enc, "7bit") {
			// Google would decode it; Fortik would classify the encoded form.
			return nil, fmt.Errorf("%w: multipart upload part with transfer encoding %q", errMalformed, enc)
		}
		b, err := io.ReadAll(p)
		if err != nil {
			return nil, fmt.Errorf("%w: multipart upload: %v", errMalformed, err)
		}
		out = append(out, relatedPart{contentType: p.Header.Get("Content-Type"), body: b})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: empty multipart upload", errMalformed)
	}
	return out, nil
}

// buildRelated builds a multipart/related body (JSON metadata + media).
func buildRelated(meta []byte, mediaType string, media []byte) (body []byte, contentType string, err error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", "application/json; charset=UTF-8")
	pw, err := mw.CreatePart(h)
	if err != nil {
		return nil, "", err
	}
	if _, err := pw.Write(meta); err != nil {
		return nil, "", err
	}
	h = textproto.MIMEHeader{}
	h.Set("Content-Type", mediaType)
	pw, err = mw.CreatePart(h)
	if err != nil {
		return nil, "", err
	}
	if _, err := pw.Write(media); err != nil {
		return nil, "", err
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), "multipart/related; boundary=" + mw.Boundary(), nil
}
