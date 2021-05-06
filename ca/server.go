package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"strings"
	"time"
)

func (ca *CA) CreateServerCertificate(name string) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	recipe := &x509.Certificate{
		SerialNumber: ca.GetNextSerial(),
		Subject: pkix.Name{
			Organization:       []string{ca.namespace},
			OrganizationalUnit: []string{hostname},
			CommonName:         name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{name},
		IPAddresses:           []net.IP{},
	}

	for _, v := range ca.SANs {
		v = strings.TrimSpace(v)

		ip := net.ParseIP(v)
		if ip != nil {
			recipe.IPAddresses = append(recipe.IPAddresses, ip)
		} else {
			recipe.DNSNames = append(recipe.DNSNames, v)
		}
	}

	// Generate keys
	priv, _ := rsa.GenerateKey(rand.Reader, 2048) // key size
	certBytes, err := x509.CreateCertificate(rand.Reader, recipe, ca.CAX509, &priv.PublicKey, ca.CATLS.PrivateKey)
	if err != nil {
		return err
	}

	err = ca.WriteToDisk(name, certBytes, priv)
	if err != nil {
		return err
	}

	return ca.Load(name)
}

func (ca *CA) GetServerCertificate(helo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Dynamicly load or create based on the requested hostname

	cn := helo.ServerName

	if cn == "" {
		host, _, err := net.SplitHostPort(helo.Conn.LocalAddr().String())
		if err != nil {
			return nil, err
		}

		cn = host
	}

	ca.Lock()
	crt, ok := ca.TLS[cn]
	ca.Unlock()

	if ok {
		return crt, nil
	}

	err := ca.LoadOrCreate(cn)
	if err != nil {
		return nil, err
	}

	ca.Lock()
	defer ca.Unlock()
	return ca.TLS[cn], nil
}
