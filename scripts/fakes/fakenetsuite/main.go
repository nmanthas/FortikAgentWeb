// Command fakenetsuite serves a LOCAL FAKE of NetSuite's REST web services
// (internal/netsuite/fakens) for scripts/demo-netsuite.sh. It is NOT NetSuite.
// It generates a throwaway RSA key pair, writes the private key (PEM) to
// -key-out for the demo to configure, and verifies Fortik's signed client
// credentials assertions with the public half.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"fortik/internal/netsuite/fakens"
)

func main() {
	port := flag.Int("port", 18400, "listen port (127.0.0.1)")
	keyOut := flag.String("key-out", "", "write the generated private key here (0600)")
	clientID := flag.String("client-id", "fortik-client-id", "accepted client id")
	certID := flag.String("cert-id", "cert-123", "accepted certificate id")
	flag.Parse()
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatal(err)
	}
	if *keyOut != "" {
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		if err := os.WriteFile(*keyOut, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			log.Fatal(err)
		}
	}
	f := fakens.New(*clientID, *certID, &k.PublicKey)
	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	f.BaseURL = "http://" + addr
	fmt.Printf("LOCAL FAKE NetSuite (not NetSuite) on http://%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, f))
}
