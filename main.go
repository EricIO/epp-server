package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/beevik/etree"
	epplib "gitlab.com/internetstiftelsen-oss/epp-lib"
)

// generateSelfSigned returns a tls.Certificate containing a self‐signed
// cert and its private key, all in memory.
func genCert() (tls.Certificate, error) {
	// 1) Generate a new RSA private key (2048 bits)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 2) Create a certificate template
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Example Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derCert},
		PrivateKey:  privKey,
	}

	return cert, nil
}

// Greeting collects greeting information and writes it to the ResponseWriter.
func Greeting(ctx context.Context, rw epplib.Writer, _ *etree.Document) {
	rw.Write(fmt.Appendf(nil, greeting, time.Now().UTC().Format(time.RFC3339)))
}

func main() {
	cert, err := genCert()
	if err != nil {
		panic(err)
	}

	mux := &epplib.CommandMux{}
	server := &epplib.Server{
		HandleCommand: mux.Handle,
		Greeting:      mux.GetGreeting,
		TLSConfig: tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAnyClientCert,
			MinVersion:   tls.VersionTLS12,
		},
		Timeout:        time.Hour,
		IdleTimeout:    30 * time.Second,
		WriteTimeout:   2 * time.Second,
		ReadTimeout:    10 * time.Second,
		MaxMessageSize: 1000,
	}

	mux.BindGreeting(Greeting)
	mux.Bind(
		epplib.NewXMLPathBuilder().
			AddOrphan("//hello", epplib.NamespaceIETFEPP10.String()).String(),
		Greeting,
	)

	addr, err := net.ResolveTCPAddr("tcp", "localhost:7000")
	if err != nil {
		panic(err)
	}

	listener, err := net.ListenTCP("tcp", addr)

	if err := server.Serve(listener); err != nil {
		panic(err)
	}
}
