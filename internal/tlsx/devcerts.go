package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// DevCerts writes a development PKI to dir: a CA (ca.crt, ca.key), a server
// certificate for hosts (server.crt, server.key) and one client certificate
// per name (client-<name>.crt/.key). For local and Compose mTLS only: pilots
// use their own PKI. Existing files are never overwritten.
func DevCerts(dir string, hosts, clients []string, validity time.Duration) ([]string, error) {
	if len(hosts) == 0 {
		return nil, errors.New("certs: at least one host")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.crt")); err == nil {
		return nil, fmt.Errorf("certs: %s already has a CA; remove the directory to regenerate", dir)
	}
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "Fortik dev CA", Organization: []string{"Fortik (development only)"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(validity), IsCA: true, BasicConstraintsValid: true,
		MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	var written []string
	write := func(name string, der []byte, key *ecdsa.PrivateKey) error {
		if err := writePEM(filepath.Join(dir, name+".crt"), "CERTIFICATE", der, 0o644); err != nil {
			return err
		}
		kb, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, name+".key"), "EC PRIVATE KEY", kb, 0o600); err != nil {
			return err
		}
		written = append(written, name+".crt", name+".key")
		return nil
	}
	if err := write("ca", caDER, caKey); err != nil {
		return nil, err
	}
	leaf := func(cn string, usage x509.ExtKeyUsage, dns []string, ips []net.IP) ([]byte, *ecdsa.PrivateKey, error) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: cn, Organization: []string{"Fortik (development only)"}},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(validity), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: dns, IPAddresses: ips}
		der, err := x509.CreateCertificate(rand.Reader, t, caCert, &k.PublicKey, caKey)
		return der, k, err
	}
	var dns []string
	var ips []net.IP
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, h)
		}
	}
	der, k, err := leaf(hosts[0], x509.ExtKeyUsageServerAuth, dns, ips)
	if err != nil {
		return nil, err
	}
	if err := write("server", der, k); err != nil {
		return nil, err
	}
	for _, c := range clients {
		der, k, err := leaf(c, x509.ExtKeyUsageClientAuth, nil, nil)
		if err != nil {
			return nil, err
		}
		if err := write("client-"+c, der, k); err != nil {
			return nil, err
		}
	}
	return written, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
