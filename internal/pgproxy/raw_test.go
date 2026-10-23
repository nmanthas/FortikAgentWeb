package pgproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fortik/internal/config"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
)

// rawClient speaks the wire protocol directly, for cases pgx cannot express.
type rawClient struct {
	t    *testing.T
	conn net.Conn
	fe   *pgproto3.Frontend
}

func (h *harness) raw(protocol uint32) *rawClient {
	t := h.t
	t.Helper()
	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	one := make([]byte, 1)
	for _, m := range []pgproto3.FrontendMessage{&pgproto3.SSLRequest{}, &pgproto3.GSSEncRequest{}} {
		b, _ := m.Encode(nil)
		if _, err := conn.Write(b); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, one); err != nil || one[0] != 'N' {
			t.Fatalf("%T: got %q %v", m, one, err)
		}
	}
	st := &pgproto3.StartupMessage{ProtocolVersion: protocol, Parameters: map[string]string{
		"user": testAgent, "database": upName, "application_name": "fortik:raw-1"}}
	b, _ := st.Encode(nil)
	if _, err := conn.Write(b); err != nil {
		t.Fatal(err)
	}
	rc := &rawClient{t: t, conn: conn, fe: pgproto3.NewFrontend(conn, conn)}
	sawNegotiate := false
	for {
		msg := rc.recv()
		switch m := msg.(type) {
		case *pgproto3.NegotiateProtocolVersion:
			sawNegotiate = true
			if m.NewestMinorProtocol != 0 {
				t.Fatalf("negotiated minor %d", m.NewestMinorProtocol)
			}
		case *pgproto3.AuthenticationCleartextPassword:
			rc.send(&pgproto3.PasswordMessage{Password: testToken})
		case *pgproto3.AuthenticationOk, *pgproto3.ParameterStatus, *pgproto3.BackendKeyData:
		case *pgproto3.ReadyForQuery:
			if protocol != pgproto3.ProtocolVersion30 && !sawNegotiate {
				t.Fatal("no NegotiateProtocolVersion for protocol 3.2 request")
			}
			return rc
		default:
			t.Fatalf("startup: unexpected %T", msg)
		}
	}
}

func (rc *rawClient) send(msgs ...pgproto3.FrontendMessage) {
	rc.t.Helper()
	for _, m := range msgs {
		rc.fe.Send(m)
	}
	if err := rc.fe.Flush(); err != nil {
		rc.t.Fatal(err)
	}
}

func (rc *rawClient) recv() pgproto3.BackendMessage {
	rc.t.Helper()
	_ = rc.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := rc.fe.Receive()
	if err != nil {
		rc.t.Fatalf("receive: %v", err)
	}
	return m
}

// expect reads messages and checks their types in order; it returns them.
func (rc *rawClient) expect(types ...string) []pgproto3.BackendMessage {
	rc.t.Helper()
	var out []pgproto3.BackendMessage
	for _, want := range types {
		m := rc.recv()
		got := typeName(m)
		if got != want {
			rc.t.Fatalf("got %s (%+v), want %s (sequence %v)", got, m, want, types)
		}
		switch x := m.(type) {
		case *pgproto3.ErrorResponse:
			c := *x
			out = append(out, &c)
		case *pgproto3.DataRow:
			vals := make([][]byte, len(x.Values))
			for i, v := range x.Values {
				vals[i] = append([]byte(nil), v...)
			}
			out = append(out, &pgproto3.DataRow{Values: vals})
		case *pgproto3.ReadyForQuery:
			out = append(out, &pgproto3.ReadyForQuery{TxStatus: x.TxStatus})
		default:
			out = append(out, m)
		}
	}
	return out
}

func typeName(m pgproto3.BackendMessage) string {
	switch m.(type) {
	case *pgproto3.ParseComplete:
		return "ParseComplete"
	case *pgproto3.BindComplete:
		return "BindComplete"
	case *pgproto3.ParameterDescription:
		return "ParameterDescription"
	case *pgproto3.RowDescription:
		return "RowDescription"
	case *pgproto3.DataRow:
		return "DataRow"
	case *pgproto3.CommandComplete:
		return "CommandComplete"
	case *pgproto3.ReadyForQuery:
		return "ReadyForQuery"
	case *pgproto3.ErrorResponse:
		return "ErrorResponse"
	case *pgproto3.NoData:
		return "NoData"
	case *pgproto3.CloseComplete:
		return "CloseComplete"
	case *pgproto3.EmptyQueryResponse:
		return "EmptyQueryResponse"
	case *pgproto3.NoticeResponse:
		return "NoticeResponse"
	case *pgproto3.PortalSuspended:
		return "PortalSuspended"
	case *pgproto3.CopyInResponse:
		return "CopyInResponse"
	}
	return "other"
}

func TestRawProtocol(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE t (id int)")
	h.dec.set("DROP_TABLE", denyRule("pg.drop"))

	t.Run("protocol 3.2 negotiates down", func(t *testing.T) {
		rc := h.raw(pgproto3.ProtocolVersion32)
		rc.send(&pgproto3.Query{String: "SELECT 1"})
		rc.expect("RowDescription", "DataRow", "CommandComplete", "ReadyForQuery")
	})

	t.Run("fastpath FunctionCall refused", func(t *testing.T) {
		rc := h.raw(pgproto3.ProtocolVersion30)
		rc.send(&pgproto3.FunctionCall{Function: 764 /* lo_import */, Arguments: [][]byte{[]byte("/etc/passwd")}, ResultFormatCode: 0})
		msgs := rc.expect("ErrorResponse", "ReadyForQuery")
		if e := msgs[0].(*pgproto3.ErrorResponse); e.Code != "42501" {
			t.Fatalf("code %s", e.Code)
		}
		// Inside a transaction block the refusal aborts it.
		rc.send(&pgproto3.Query{String: "BEGIN"})
		rc.expect("CommandComplete", "ReadyForQuery")
		rc.send(&pgproto3.FunctionCall{Function: 764, Arguments: [][]byte{[]byte("/etc/passwd")}})
		msgs = rc.expect("ErrorResponse", "ReadyForQuery")
		if msgs[1].(*pgproto3.ReadyForQuery).TxStatus != 'E' {
			t.Fatalf("tx status %c", msgs[1].(*pgproto3.ReadyForQuery).TxStatus)
		}
		rc.send(&pgproto3.Query{String: "ROLLBACK"})
		rc.expect("CommandComplete", "ReadyForQuery")
	})

	t.Run("Flush without Sync gets responses", func(t *testing.T) {
		rc := h.raw(pgproto3.ProtocolVersion30)
		rc.send(&pgproto3.Parse{Name: "s1", Query: "SELECT $1::int AS v"}, &pgproto3.Describe{ObjectType: 'S', Name: "s1"}, &pgproto3.Flush{})
		rc.expect("ParseComplete", "ParameterDescription", "RowDescription")
		rc.send(&pgproto3.Bind{PreparedStatement: "s1", Parameters: [][]byte{[]byte("41")}}, &pgproto3.Execute{}, &pgproto3.Flush{})
		msgs := rc.expect("BindComplete", "DataRow", "CommandComplete")
		if string(msgs[1].(*pgproto3.DataRow).Values[0]) != "41" {
			t.Fatal("wrong value")
		}
		rc.send(&pgproto3.Sync{})
		rc.expect("ReadyForQuery")
	})

	t.Run("refused Parse answers before Sync and discards until Sync", func(t *testing.T) {
		rc := h.raw(pgproto3.ProtocolVersion30)
		rc.send(&pgproto3.Parse{Name: "bad", Query: "DROP TABLE t"}, &pgproto3.Flush{})
		msgs := rc.expect("ErrorResponse")
		if e := msgs[0].(*pgproto3.ErrorResponse); e.Code != "42501" || e.Detail == "" {
			t.Fatalf("error %+v", e)
		}
		rc.send(&pgproto3.Bind{PreparedStatement: "bad"}, &pgproto3.Execute{}, &pgproto3.Sync{})
		rc.expect("ReadyForQuery")
		rc.send(&pgproto3.Query{String: "SELECT count(*) FROM t"})
		rc.expect("RowDescription", "DataRow", "CommandComplete", "ReadyForQuery")
	})

	t.Run("pipelined Parse/Bind/Execute then refused Parse in same batch", func(t *testing.T) {
		rc := h.raw(pgproto3.ProtocolVersion30)
		rc.send(
			&pgproto3.Parse{Query: "INSERT INTO t VALUES (1)"}, &pgproto3.Bind{}, &pgproto3.Execute{},
			&pgproto3.Parse{Name: "x", Query: "DROP TABLE t"}, &pgproto3.Bind{PreparedStatement: "x"}, &pgproto3.Execute{},
			&pgproto3.Sync{})
		msgs := rc.expect("ParseComplete", "BindComplete", "CommandComplete", "ErrorResponse", "ReadyForQuery")
		e := msgs[3].(*pgproto3.ErrorResponse)
		if e.Code != "42501" || e.Where != "" || e.Detail == "" {
			t.Fatalf("error %+v", e)
		}
		if n := h.count("SELECT count(*) FROM t"); n != 0 {
			t.Fatal("insert in the refused batch committed")
		}
	})

	t.Run("pipelined simple queries keep order", func(t *testing.T) {
		rc := h.raw(pgproto3.ProtocolVersion30)
		rc.send(&pgproto3.Query{String: "SELECT pg_sleep(0.2), 1"}, &pgproto3.Query{String: "DROP TABLE t"}, &pgproto3.Query{String: "SELECT 2"})
		msgs := rc.expect("RowDescription", "DataRow", "CommandComplete", "ReadyForQuery",
			"ErrorResponse", "ReadyForQuery",
			"RowDescription", "DataRow", "CommandComplete", "ReadyForQuery")
		if e := msgs[4].(*pgproto3.ErrorResponse); e.Code != "42501" {
			t.Fatalf("code %s", e.Code)
		}
	})

	t.Run("bad instance id rejected", func(t *testing.T) {
		_, err := h.connectErrApp(testAgent, testToken, upName, "fortik:bad id with spaces")
		if pe := pgErr(t, err); pe.Code != "28000" {
			t.Fatalf("got %s", pe.Code)
		}
	})
}

func (h *harness) connectErrApp(agent, token, db, app string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(h.url(agent, token, db))
	if err != nil {
		return nil, err
	}
	cfg.RuntimeParams["application_name"] = app
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgx.ConnectConfig(ctx, cfg)
}

func TestNotificationsRelayed(t *testing.T) {
	h := newHarness(t)
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	if _, err := c.Exec(bg, "LISTEN fortik_chan"); err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() {
		time.Sleep(200 * time.Millisecond)
		_, err := h.admin.Exec(context.Background(), "NOTIFY fortik_chan, 'hello'")
		sent <- err
	}()
	ctx, cancel := context.WithTimeout(bg, 5*time.Second)
	defer cancel()
	n, err := c.WaitForNotification(ctx)
	if serr := <-sent; serr != nil {
		t.Fatal(serr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if n.Channel != "fortik_chan" || n.Payload != "hello" {
		t.Fatalf("notification %+v", n)
	}
}

func TestGracefulShutdown(t *testing.T) {
	h := newHarness(t)
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	if _, err := c.Exec(bg, "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	// A connection stuck in startup must not delay shutdown.
	stuck, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer stuck.Close()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if err := h.stop(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("shutdown took %v", d)
	}
	if _, err := c.Exec(bg, "SELECT 1"); err == nil {
		t.Fatal("session still usable after shutdown")
	}
	if _, err := net.DialTimeout("tcp", h.addr, time.Second); err == nil {
		t.Fatal("still accepting after shutdown")
	}
}

func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certFile, keyFile
}

func TestTLS(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	h := newHarnessWith(t, func(c *config.PGProxyConfig) { c.TLSCertFile, c.TLSKeyFile = certFile, keyFile })
	cfg, err := pgx.ParseConfig(strings.Replace(h.url(testAgent, testToken, upName), "sslmode=disable", "sslmode=require", 1))
	if err != nil {
		t.Fatal(err)
	}
	c, err := pgx.ConnectConfig(bg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(bg)
	if _, ok := c.PgConn().Conn().(*tls.Conn); !ok {
		t.Fatalf("connection is not TLS: %T", c.PgConn().Conn())
	}
	var v int
	if err := c.QueryRow(bg, "SELECT 42").Scan(&v); err != nil || v != 42 {
		t.Fatalf("query over TLS: %v", err)
	}
}
