package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	mrand "math/rand"
	"os"
	"time"
)

func (ca *CA) CreateCA() error {
	hostname, err := os.Hostname()
	if err != nil {
		return nil
	}

	// Create a 10year CA cert
	recipe := &x509.Certificate{
		SerialNumber: ca.GetNextSerial(),
		Subject: pkix.Name{
			Organization:       []string{ca.namespace},
			OrganizationalUnit: []string{hostname},
			CommonName:         ca.namespace + " CA for " + hostname,
		},
		SubjectKeyId:          bigIntHash(big.NewInt(int64(mrand.Int()))),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Generate keys
	priv, _ := rsa.GenerateKey(rand.Reader, 2048) // key size
	certBytes, err := x509.CreateCertificate(rand.Reader, recipe, recipe, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	err = ca.WriteToDisk("ca", certBytes, priv)
	if err != nil {
		return err
	}

	return ca.Load("ca")
}

func (ca *CA) GetNextSerial() *big.Int {
	// TODO: Make something more sofisticated than counting the amount of certs :)
	certificates := ca.GetCertificates()
	return big.NewInt(int64(1000 + len(certificates)))
}

func (ca *CA) GetTlsConfig() (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca.CAX509)

	return &tls.Config{
		// Dynamic load certificates
		GetCertificate: ca.GetServerCertificate,

		// Needed to verify client certificates
		ClientCAs: caCertPool,
		// Certificates: []tls.Certificate{*c.CA.TLS},
		ClientAuth: tls.VerifyClientCertIfGiven,
	}, nil
}
