package google

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/gateway"
)

// opState carries the mapped request from Map to Enrich and Forward.
type opState struct {
	unknown  bool
	api      string // gmail | drive
	endpoint string // e.g. "gmail.users.messages.send"
	method   string
	base     string     // upstream base URL
	segs     []string   // upstream path segments (unescaped, validated)
	query    url.Values // sanitised query
	scopes   []string   // minimal OAuth scopes for this endpoint
	userID   string     // Gmail {userId} as sent ("me" or the workspace user)
	send     *sendState
	share    *shareState
}

type sendState struct {
	draftID  string
	threadID string
	msg      *message // nil until known (drafts.send without content: fetched in Enrich)
}

type shareState struct {
	create       bool
	fileID       string
	permissionID string
	shareType    string // user | group | domain | anyone (update: from the existing permission)
	role         string
	email        string
	domain       string
	fields       map[string]any // canonical body forwarded when not narrowed
}

// url is the upstream URL with each path segment re-escaped.
func (st *opState) url() string {
	parts := make([]string, len(st.segs))
	for i, s := range st.segs {
		parts[i] = url.PathEscape(s)
	}
	u := st.base + "/" + strings.Join(parts, "/")
	if q := st.query.Encode(); q != "" {
		u += "?" + q
	}
	return u
}

// segPattern bounds path segments to the characters Google ids, user ids
// (email addresses) and method names use; anything else is UNKNOWN.
var segPattern = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,256}$`)

// strippedQuery are agent-supplied credentials Google would otherwise
// consider alongside Fortik's token.
var strippedQuery = []string{"access_token", "oauth_token", "key"}

func unknownOp(api, endpoint, reason string) gateway.Op {
	system := api
	if system == "" {
		system = "google"
	}
	return gateway.Op{
		Action: action.Action{System: system, Verb: "UNKNOWN", Target: map[string]any{"endpoint": endpoint, "reason": reason}},
		State:  &opState{unknown: true, api: api},
	}
}

// Map classifies a /gw/google/... request. It never returns an error:
// anything it cannot classify becomes verb UNKNOWN (denied by POL-002).
func (a *Adapter) Map(ctx context.Context, p authz.Principal, r *http.Request, body []byte) (gateway.Op, error) {
	op := a.route(ctx, p, r, body)
	op.Body = body
	return op, nil
}

func (a *Adapter) route(ctx context.Context, p authz.Principal, r *http.Request, body []byte) gateway.Op {
	escaped := r.URL.EscapedPath()
	rawPath, ok := strings.CutPrefix(escaped, "/gw/google/")
	label := r.Method + " /" + rawPath
	if len(label) > 300 {
		label = label[:300]
	}
	if !ok || rawPath == "" {
		return unknownOp("", label, "not a Google API path")
	}
	var segs []string
	for _, s := range strings.Split(rawPath, "/") {
		u, err := url.PathUnescape(s)
		if err != nil || !segPattern.MatchString(u) || strings.Trim(u, ".") == "" {
			return unknownOp("", label, "malformed path segment")
		}
		segs = append(segs, u)
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return unknownOp("", label, "malformed query string")
	}
	for _, k := range strippedQuery {
		q.Del(k)
	}
	upload := segs[0] == "upload"
	rest := segs
	if upload {
		rest = segs[1:]
	}
	if len(q["uploadType"]) > 1 {
		return unknownOp("", label, "repeated uploadType")
	}
	if ut := q.Get("uploadType"); upload && ut != "media" && ut != "multipart" {
		return unknownOp("", label, "only uploadType=media and uploadType=multipart are supported")
	} else if !upload && q.Has("uploadType") {
		return unknownOp("", label, "uploadType on a non-upload path")
	}
	st := &opState{method: r.Method, segs: segs, query: q}
	switch {
	case len(rest) >= 4 && rest[0] == "gmail" && rest[1] == "v1" && rest[2] == "users":
		st.api, st.base = "gmail", a.gmailBase
		return a.routeGmail(ctx, p, r, body, st, rest[3], rest[4:], upload, label)
	case len(rest) >= 3 && rest[0] == "drive" && rest[1] == "v3" && rest[2] == "files":
		st.api, st.base = "drive", a.driveBase
		if upload {
			st.base = a.driveUpload
		}
		return a.routeDrive(r, body, st, rest[3:], upload, label)
	}
	return unknownOp("", label, "unsupported Google API")
}

func is(rest []string, parts ...string) bool {
	if len(rest) != len(parts) {
		return false
	}
	for i := range parts {
		if parts[i] != "*" && rest[i] != parts[i] {
			return false
		}
	}
	return true
}

func (st *opState) op(endpoint string, verb action.Verb, scopes []string, target map[string]any) gateway.Op {
	st.endpoint, st.scopes = endpoint, scopes
	t := map[string]any{"endpoint": endpoint}
	for k, v := range target {
		t[k] = v
	}
	return gateway.Op{Action: action.Action{System: st.api, Verb: verb, Target: t}, State: st}
}

// --- Gmail -------------------------------------------------------------------

func (a *Adapter) routeGmail(ctx context.Context, p authz.Principal, r *http.Request, body []byte, st *opState, userID string, rest []string, upload bool, label string) gateway.Op {
	const api = "gmail"
	if userID != "me" {
		ws, err := a.subject(ctx, p.Name)
		if err != nil {
			a.log.Warn("workspace identity lookup failed", "agent_id", p.Name, "err", err)
			return unknownOp(api, label, "workspace identity lookup failed")
		}
		if ws == "" || !strings.EqualFold(userID, ws) {
			return unknownOp(api, label, `userId is neither "me" nor the agent's workspace_user`)
		}
	}
	st.userID = userID
	m := r.Method
	switch {
	case m == http.MethodPost && is(rest, "messages", "send"):
		return a.mapSend(r, body, st, upload, label)
	case upload:
		return unknownOp(api, label, "upload is only supported for messages.send")
	case m == http.MethodPost && is(rest, "drafts", "send"):
		return a.mapDraftSend(body, st, label)
	case m == http.MethodGet && is(rest, "messages"):
		return st.op("gmail.users.messages.list", action.VerbRead, []string{ScopeGmailReadonly}, nil)
	case m == http.MethodGet && is(rest, "messages", "*"):
		return st.op("gmail.users.messages.get", action.VerbRead, []string{ScopeGmailReadonly}, map[string]any{"message_id": rest[1]})
	case m == http.MethodGet && is(rest, "messages", "*", "attachments", "*"):
		return st.op("gmail.users.messages.attachments.get", action.VerbRead, []string{ScopeGmailReadonly}, map[string]any{"message_id": rest[1]})
	case m == http.MethodGet && is(rest, "profile"):
		return st.op("gmail.users.getProfile", action.VerbRead, []string{ScopeGmailReadonly}, nil)
	case m == http.MethodGet && is(rest, "labels"):
		return st.op("gmail.users.labels.list", action.VerbRead, []string{ScopeGmailReadonly}, nil)
	case m == http.MethodPost && is(rest, "messages", "*", "trash"):
		return st.op("gmail.users.messages.trash", action.VerbDelete, []string{ScopeGmailModify}, map[string]any{"message_id": rest[1], "count": 1})
	case m == http.MethodDelete && is(rest, "messages", "*"):
		return st.op("gmail.users.messages.delete", action.VerbDelete, []string{ScopeGmailFull}, map[string]any{"message_id": rest[1], "count": 1})
	case m == http.MethodPost && is(rest, "messages", "batchDelete"):
		obj, err := object(body)
		var ids []string
		if err == nil {
			err = onlyKeys(obj, "ids")
		}
		if err == nil {
			err = json.Unmarshal(obj["ids"], &ids)
		}
		if err != nil {
			return unknownOp(api, label, "batchDelete body not understood")
		}
		return st.op("gmail.users.messages.batchDelete", action.VerbDelete, []string{ScopeGmailFull}, map[string]any{"count": len(ids)})
	case m == http.MethodPost && is(rest, "settings", "forwardingAddresses"):
		// Redirects mail out of the mailbox: a permission change (GRANT).
		return st.op("gmail.users.settings.forwardingAddresses.create", action.VerbGrant, []string{ScopeGmailSettingsSharing},
			map[string]any{"operation": "forwarding_address", "forward_to": bodyString(body, "forwardingemail")})
	case m == http.MethodPost && is(rest, "settings", "sendAs"):
		return st.op("gmail.users.settings.sendAs.create", action.VerbGrant, []string{ScopeGmailSettingsSharing},
			map[string]any{"operation": "send_as", "send_as": bodyString(body, "sendasemail")})
	case m == http.MethodPost && is(rest, "settings", "filters"):
		fwd, err := filterForward(body)
		if err != nil {
			return unknownOp(api, label, "filter body not understood")
		}
		if fwd == "" {
			return unknownOp(api, label, "only filters that forward mail are classified")
		}
		return st.op("gmail.users.settings.filters.create", action.VerbGrant, []string{ScopeGmailSettingsBasic},
			map[string]any{"operation": "filter_forward", "forward_to": fwd})
	}
	return unknownOp(api, label, "unsupported Gmail endpoint")
}

// bodyString best-effort extracts a lower-cased string field for the target.
func bodyString(body []byte, key string) string {
	obj, err := object(body)
	if err != nil {
		return ""
	}
	s, _, _ := jsonString(obj, key)
	return strings.ToLower(strings.TrimSpace(s))
}

// filterForward returns action.forward of a filter (or "").
func filterForward(body []byte) (string, error) {
	obj, err := object(body)
	if err != nil {
		return "", err
	}
	act, ok := obj["action"]
	if !ok || string(act) == "null" {
		return "", nil
	}
	ao, err := object(act)
	if err != nil {
		return "", err
	}
	fwd, _, err := jsonString(ao, "forward")
	return strings.ToLower(strings.TrimSpace(fwd)), err
}

// mapSend parses users.messages.send: JSON {raw, threadId} or an upload
// (media: the RFC 822 message; multipart: JSON metadata + message/rfc822).
func (a *Adapter) mapSend(r *http.Request, body []byte, st *opState, upload bool, label string) gateway.Op {
	const api = "gmail"
	ss := &sendState{}
	var raw []byte
	switch {
	case !upload:
		obj, err := object(body)
		if err == nil {
			err = onlyKeys(obj, "raw", "threadid", "labelids")
		}
		var rawB64 string
		if err == nil {
			rawB64, _, err = jsonString(obj, "raw")
		}
		if err == nil {
			ss.threadID, _, err = jsonString(obj, "threadid")
		}
		if err == nil {
			raw, err = decodeRaw(rawB64)
		}
		if err != nil {
			return unknownOp(api, label, "send body not understood: "+err.Error())
		}
	case st.query.Get("uploadType") == "media":
		raw = body
	default:
		parts, err := parseRelated(r.Header.Get("Content-Type"), body)
		if err == nil && len(parts) != 2 {
			err = errMalformed
		}
		if err == nil && !mediaIs(parts[1].contentType, "message/rfc822") {
			err = errors.New("media part must be message/rfc822")
		}
		var meta map[string]json.RawMessage
		if err == nil {
			meta, err = object(parts[0].body)
		}
		if err == nil {
			err = onlyKeys(meta, "threadid", "labelids")
		}
		if err == nil {
			ss.threadID, _, err = jsonString(meta, "threadid")
		}
		if err != nil {
			return unknownOp(api, label, "multipart send not understood: "+err.Error())
		}
		raw = parts[1].body
	}
	if ss.threadID != "" && !segPattern.MatchString(ss.threadID) {
		return unknownOp(api, label, "malformed threadId")
	}
	msg, err := parseMessage(raw)
	if err != nil {
		return unknownOp(api, label, "message not understood: "+err.Error())
	}
	ss.msg = msg
	st.send = ss
	op := st.op("gmail.users.messages.send", action.VerbSend, []string{ScopeGmailSend}, nil)
	a.classifySend(&op, st, settings{}, false)
	return op
}

func mediaIs(ct, want string) bool {
	mt, _, _ := strings.Cut(ct, ";")
	return strings.EqualFold(strings.TrimSpace(mt), want)
}

// mapDraftSend parses users.drafts.send {id, message?: {raw, threadId}}.
// Fortik sends exactly the content it classified (the supplied raw, or the
// stored draft fetched in Enrich) through messages.send, then deletes the
// draft, so a draft edited after classification can never go out.
func (a *Adapter) mapDraftSend(body []byte, st *opState, label string) gateway.Op {
	const api = "gmail"
	ss := &sendState{}
	obj, err := object(body)
	if err == nil {
		err = onlyKeys(obj, "id", "message")
	}
	if err == nil {
		ss.draftID, _, err = jsonString(obj, "id")
	}
	if err == nil && !segPattern.MatchString(ss.draftID) {
		err = errors.New("draft id missing or malformed")
	}
	if err == nil {
		if mraw, ok := obj["message"]; ok && string(mraw) != "null" {
			var mo map[string]json.RawMessage
			mo, err = object(mraw)
			if err == nil {
				err = onlyKeys(mo, "raw", "threadid", "id", "labelids")
			}
			var rawB64 string
			if err == nil {
				rawB64, _, err = jsonString(mo, "raw")
			}
			if err == nil {
				ss.threadID, _, err = jsonString(mo, "threadid")
			}
			if err == nil && rawB64 != "" {
				var raw []byte
				if raw, err = decodeRaw(rawB64); err == nil {
					ss.msg, err = parseMessage(raw)
				}
			}
		}
	}
	if err == nil && ss.threadID != "" && !segPattern.MatchString(ss.threadID) {
		err = errors.New("malformed threadId")
	}
	if err != nil {
		return unknownOp(api, label, "drafts.send body not understood: "+err.Error())
	}
	st.send = ss
	op := st.op("gmail.users.drafts.send", action.VerbSend, []string{ScopeGmailCompose}, nil)
	a.classifySend(&op, st, settings{}, false)
	return op
}

// classifySend fills the SEND target and payload summary. Without the
// integration every recipient domain counts as external (fail closed).
func (a *Adapter) classifySend(op *gateway.Op, st *opState, s settings, configured bool) {
	t := map[string]any{"endpoint": st.endpoint, "user_id": st.userID}
	if st.send.draftID != "" {
		t["draft_id"] = st.send.draftID
	}
	m := st.send.msg
	if m == nil {
		t["recipients_unknown"] = true
		t["external_domains"] = 1
		op.Action.Target = t
		op.Action.PayloadSummary = summaryKeepLabels(op.Action.PayloadSummary, 0, 0, 0)
		return
	}
	ext := 0
	for _, d := range m.domains() {
		if !configured || !s.isInternal(d) {
			ext++
		}
	}
	budget := maxTargetAddrs
	take := func(l []string) []string {
		if len(l) > budget {
			t["addresses_truncated"] = true
			l = l[:budget]
		}
		budget -= len(l)
		return append([]string{}, l...)
	}
	t["to"], t["cc"], t["bcc"] = take(m.to), take(m.cc), take(m.bcc)
	t["external_domains"] = ext
	t["attachment_bytes"] = m.attachmentBytes
	op.Action.Target = t
	op.Action.PayloadSummary = summaryKeepLabels(op.Action.PayloadSummary, len(m.recipients()), m.attachments, int64(len(m.raw)))
}

func summaryKeepLabels(prev action.PayloadSummary, recipients, attachments int, size int64) action.PayloadSummary {
	return action.PayloadSummary{Recipients: recipients, Attachments: attachments, Bytes: size, DataLabels: prev.DataLabels}
}

// --- Drive -------------------------------------------------------------------

var (
	shareTypes = map[string]bool{"user": true, "group": true, "domain": true, "anyone": true}
	shareRoles = map[string]bool{"owner": true, "organizer": true, "fileOrganizer": true, "writer": true, "commenter": true, "reader": true}
)

func (a *Adapter) routeDrive(r *http.Request, body []byte, st *opState, rest []string, upload bool, label string) gateway.Op {
	const api = "drive"
	read := []string{ScopeDriveReadonly}
	full := []string{ScopeDrive}
	m := r.Method
	switch {
	case m == http.MethodGet && upload:
		return unknownOp(api, label, "GET on an upload path")
	case m == http.MethodGet && is(rest):
		return st.op("drive.files.list", action.VerbRead, read, nil)
	case m == http.MethodGet && is(rest, "*"):
		t := map[string]any{"file_id": rest[0]}
		if alt := st.query.Get("alt"); alt != "" {
			t["alt"] = alt
		}
		return st.op("drive.files.get", action.VerbRead, read, t)
	case m == http.MethodGet && is(rest, "*", "export"):
		return st.op("drive.files.export", action.VerbRead, read, map[string]any{"file_id": rest[0]})
	case m == http.MethodGet && is(rest, "*", "permissions"):
		return st.op("drive.permissions.list", action.VerbRead, read, map[string]any{"file_id": rest[0]})
	case m == http.MethodGet && is(rest, "*", "permissions", "*"):
		return st.op("drive.permissions.get", action.VerbRead, read, map[string]any{"file_id": rest[0], "permission_id": rest[2]})
	case m == http.MethodPost && is(rest):
		ep := "drive.files.create"
		if upload {
			ep = "drive.files.create.upload"
		}
		if reason := placesIntoParent(r, body, st, upload); reason != "" {
			return unknownOp(api, label, reason)
		}
		return st.op(ep, action.VerbWrite, full, nil)
	case m == http.MethodPatch && is(rest, "*"):
		return a.mapFileUpdate(r, body, st, rest[0], upload, label)
	case upload:
		return unknownOp(api, label, "unsupported Drive upload endpoint")
	case m == http.MethodPost && is(rest, "*", "copy"):
		if reason := placesIntoParent(r, body, st, false); reason != "" {
			return unknownOp(api, label, reason)
		}
		return st.op("drive.files.copy", action.VerbWrite, full, map[string]any{"file_id": rest[0]})
	case m == http.MethodDelete && is(rest, "trash"):
		return st.op("drive.files.emptyTrash", action.VerbDelete, full, map[string]any{"operation": "empty_trash"})
	case m == http.MethodDelete && is(rest, "*"):
		return st.op("drive.files.delete", action.VerbDelete, full, map[string]any{"file_id": rest[0]})
	case m == http.MethodPost && is(rest, "*", "permissions"):
		return a.mapShare(body, st, rest[0], "", label)
	case m == http.MethodPatch && is(rest, "*", "permissions", "*"):
		return a.mapShare(body, st, rest[0], rest[2], label)
	case m == http.MethodDelete && is(rest, "*", "permissions", "*"):
		// Removing access narrows sharing: an ordinary write.
		return st.op("drive.permissions.delete", action.VerbWrite, full, map[string]any{"file_id": rest[0], "permission_id": rest[2]})
	}
	return unknownOp(api, label, "unsupported Drive endpoint")
}

// placesIntoParent reports why a Drive request that puts a file into a chosen
// folder cannot be classified, or "" when it does not. A file inherits its
// folder's sharing, so adding a parent (addParents, or a "parents" field on
// create/copy/update metadata) can expose it outside the organisation without
// any permissions call. Fortik cannot yet classify the destination folder's
// exposure, so such requests are refused (UNKNOWN) rather than passed as plain
// WRITEs that bypass the share policy (POL-211/212/213, POL-023).
func placesIntoParent(r *http.Request, body []byte, st *opState, upload bool) string {
	for k := range st.query {
		if normKey(k) == "addparents" {
			return "addParents moves the file into a folder whose sharing cannot be classified"
		}
	}
	meta := body
	if upload {
		if st.query.Get("uploadType") == "media" {
			return ""
		}
		parts, err := parseRelated(r.Header.Get("Content-Type"), body)
		if err != nil || len(parts) == 0 {
			return "multipart body not understood"
		}
		meta = parts[0].body
	}
	if len(strings.TrimSpace(string(meta))) == 0 {
		return ""
	}
	obj, err := object(meta)
	if err != nil {
		return "file metadata not understood"
	}
	if _, ok := obj["parents"]; ok {
		return "parents places the file into a folder whose sharing cannot be classified"
	}
	return ""
}

// mapFileUpdate: files.update is a WRITE, or a DELETE when it trashes.
func (a *Adapter) mapFileUpdate(r *http.Request, body []byte, st *opState, fileID string, upload bool, label string) gateway.Op {
	if reason := placesIntoParent(r, body, st, upload); reason != "" {
		return unknownOp("drive", label, reason)
	}
	var meta []byte
	switch {
	case upload && st.query.Get("uploadType") == "media":
	case upload:
		parts, err := parseRelated(r.Header.Get("Content-Type"), body)
		if err != nil {
			return unknownOp("drive", label, "multipart update not understood")
		}
		meta = parts[0].body
	default:
		meta = body
	}
	trashed := false
	if len(strings.TrimSpace(string(meta))) > 0 {
		obj, err := object(meta)
		if err == nil {
			trashed, _, err = jsonBool(obj, "trashed")
		}
		if err != nil {
			return unknownOp("drive", label, "file metadata not understood")
		}
	}
	if trashed {
		return st.op("drive.files.update", action.VerbDelete, []string{ScopeDrive}, map[string]any{"file_id": fileID, "operation": "trash"})
	}
	return st.op("drive.files.update", action.VerbWrite, []string{ScopeDrive}, map[string]any{"file_id": fileID})
}

// mapShare maps permissions.create (permissionID == "") and permissions.update.
// Shares are EXPORT (POL-211/212/213, narrowed and recorded); an ownership
// transfer is a GRANT. The body is re-serialised from the parsed fields so
// Google acts on exactly what was classified.
func (a *Adapter) mapShare(body []byte, st *opState, fileID, permissionID, label string) gateway.Op {
	const api = "drive"
	obj, err := object(body)
	if err != nil {
		return unknownOp(api, label, "permission body not understood")
	}
	sh := &shareState{create: permissionID == "", fileID: fileID, permissionID: permissionID, fields: map[string]any{}}
	allowed := []string{"role", "expirationtime", "view", "pendingowner"}
	if sh.create {
		allowed = append(allowed, "type", "emailaddress", "domain", "allowfilediscovery")
	}
	if err := onlyKeys(obj, allowed...); err != nil {
		return unknownOp(api, label, "permission body has unclassified fields")
	}
	canon := map[string]string{"type": "type", "role": "role", "emailaddress": "emailAddress", "domain": "domain",
		"expirationtime": "expirationTime", "view": "view"}
	for nk, name := range canon {
		v, ok, err := jsonString(obj, nk)
		if err != nil {
			return unknownOp(api, label, "permission body not understood")
		}
		if ok {
			sh.fields[name] = v
		}
	}
	for nk, name := range map[string]string{"allowfilediscovery": "allowFileDiscovery", "pendingowner": "pendingOwner"} {
		v, ok, err := jsonBool(obj, nk)
		if err != nil {
			return unknownOp(api, label, "permission body not understood")
		}
		if ok {
			sh.fields[name] = v
		}
	}
	sh.role, _ = sh.fields["role"].(string)
	if sh.role != "" && !shareRoles[sh.role] {
		return unknownOp(api, label, "unknown permission role")
	}
	if sh.create {
		sh.shareType, _ = sh.fields["type"].(string)
		sh.email, _ = sh.fields["emailAddress"].(string)
		sh.email = strings.ToLower(strings.TrimSpace(sh.email))
		sh.domain, _ = sh.fields["domain"].(string)
		sh.domain = normDomain(sh.domain)
		switch {
		case !shareTypes[sh.shareType]:
			return unknownOp(api, label, "unknown permission type")
		case sh.role == "":
			return unknownOp(api, label, "permission role is required")
		case (sh.shareType == "user" || sh.shareType == "group") && domainOf(sh.email) == "":
			return unknownOp(api, label, "user/group permission needs an emailAddress")
		case sh.shareType == "domain" && sh.domain == "":
			return unknownOp(api, label, "domain permission needs a domain")
		}
	}
	st.share = sh
	ownership := sh.role == "owner" || strings.EqualFold(st.query.Get("transferOwnership"), "true") || sh.fields["pendingOwner"] == true
	ep := "drive.permissions.create"
	if !sh.create {
		ep = "drive.permissions.update"
	}
	verb := action.VerbExport
	if ownership {
		verb = action.VerbGrant
	}
	op := st.op(ep, verb, []string{ScopeDrive}, nil)
	a.classifyShare(&op, st, settings{}, false)
	if ownership {
		op.Action.Target["operation"] = "transfer_ownership"
	}
	return op
}

// classifyShare fills the share target. Without the integration every
// grantee counts as external (fail closed).
func (a *Adapter) classifyShare(op *gateway.Op, st *opState, s settings, configured bool) {
	sh := st.share
	shareType := sh.shareType
	if shareType == "" {
		shareType = "unknown"
	}
	t := map[string]any{"endpoint": st.endpoint, "operation": "share", "share_type": shareType, "file_id": sh.fileID}
	if prev, ok := op.Action.Target["operation"]; ok && prev == "transfer_ownership" {
		t["operation"] = prev
	}
	if sh.role != "" {
		t["role"] = sh.role
	}
	if sh.permissionID != "" {
		t["permission_id"] = sh.permissionID
	}
	external := true
	switch shareType {
	case "user", "group":
		t["grantee"] = sh.email
		d := domainOf(sh.email)
		external = !(configured && d != "" && s.isInternal(d))
	case "domain":
		t["grantee"] = sh.domain
		external = !(configured && sh.domain != "" && s.isInternal(sh.domain))
	}
	t["external"] = external
	op.Action.Target = t
}
