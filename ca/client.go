package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func (ca *CA) CreateCertificateFromRequest(csr []byte, templateEnhancer ...func(template *x509.Certificate)) ([]byte, error) {
	pemBlock, _ := pem.Decode(csr)
	if pemBlock == nil {
		return nil, fmt.Errorf("pem.Decode returned no data")
	}
	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if err = clientCSR.CheckSignature(); err != nil {
		return nil, err
	}

	// create client certificate template
	clientCRTTemplate := &x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: ca.GetNextSerial(),
		Issuer:       ca.CAX509.Subject,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	for _, v := range templateEnhancer {
		v(clientCRTTemplate)
	}

	// create client certificate from template and CA public key
	certBytes, err := x509.CreateCertificate(rand.Reader, clientCRTTemplate, ca.CAX509, clientCRTTemplate.PublicKey, ca.CATLS.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Save the certificate to file
	err = ca.WriteToDisk(clientCSR.Subject.CommonName, certBytes, nil)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}), nil
}

func (ca *CA) CreateClientCertificate(uuid string) ([]byte, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	recipe := &x509.Certificate{
		SerialNumber: ca.GetNextSerial(),
		Issuer:       ca.CAX509.Subject,
		Subject: pkix.Name{
			Organization:       []string{ca.namespace},
			OrganizationalUnit: []string{hostname},
			CommonName:         uuid,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Generate keys
	priv, _ := rsa.GenerateKey(rand.Reader, 2048) // key size
	certBytes, err := x509.CreateCertificate(rand.Reader, recipe, ca.CAX509, &priv.PublicKey, ca.CATLS.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Save the certificate to file
	err = ca.WriteToDisk(uuid, certBytes, priv)
	if err != nil {
		return nil, err
	}

	certX509, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	password := ""
	caCerts := []*x509.Certificate{
		ca.CAX509,
	}

	return pkcs12.Encode(rand.Reader, priv, certX509, caCerts, password)
}
