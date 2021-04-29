package ca

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/sirupsen/logrus"
)

func (ca *CA) LoadOrCreate(name string) error {
	err := ca.Load(name)
	if err == nil {
		return nil
	}

	if name == "ca" {
		return ca.CreateCA()
	}
	return ca.CreateServerCertificate(name)
}

func (ca *CA) Load(name string) error {
	if _, err := os.Stat(ca.path); os.IsNotExist(err) {
		os.Mkdir(ca.path, 0755)
	}

	certTLS, err := tls.LoadX509KeyPair(path.Join(ca.path, name+".crt"), path.Join(ca.path, name+".key"))
	if err != nil {
		return err
	}
	certX509, err := x509.ParseCertificate(certTLS.Certificate[0])
	if err != nil {
		return err
	}

	if name == "ca" {
		rawfile, err := ioutil.ReadFile(path.Join(ca.path, name+".crt"))
		if err != nil {
			return err
		}

		ca.Lock()
		ca.CATLS = &certTLS
		ca.CAX509 = certX509
		ca.CAFile = rawfile
		ca.Unlock()
		return nil
	}
	ca.Lock()
	ca.TLS[name] = &certTLS
	ca.X509[name] = certX509
	ca.Unlock()

	logrus.Info("Loaded " + name + ".key")
	return nil
}

func (ca *CA) WriteToDisk(name string, certBytes []byte, privateKey *rsa.PrivateKey) error {
	if _, err := os.Stat(ca.path); os.IsNotExist(err) {
		os.Mkdir(ca.path, 0644)
	}

	// Write public key
	certOut, err := os.Create(path.Join(ca.path, name+".crt"))
	if err != nil {
		return err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return err
	}
	certOut.Close()
	logrus.Info("Wrote " + name + ".crt\n")

	if privateKey != nil {
		// Write private key
		keyOut, err := os.OpenFile(path.Join(ca.path, name+".key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
		if err != nil {
			return err
		}
		keyOut.Close()
		logrus.Info("Wrote " + name + ".key\n")
	}

	return nil
}

func (ca *CA) GetCertificates() []*x509.Certificate {
	files, err := ioutil.ReadDir(storagePath)
	if err != nil {
		return nil
	}

	certs := make([]*x509.Certificate, 0)

	for _, f := range files {
		n := strings.Split(f.Name(), ".")
		if n[len(n)-1] != "crt" {
			continue
		}

		cf, err := ioutil.ReadFile(path.Join(storagePath, f.Name()))
		if err != nil {
			logrus.Warnf("Failed to read certificate %s: %s", f.Name(), err.Error())
			continue
		}

		cpb, _ := pem.Decode(cf)

		crt, err := x509.ParseCertificate(cpb.Bytes)
		if err != nil {
			logrus.Warnf("Failed to read certificate %s: %s", f.Name(), err.Error())
			continue
		}

		certs = append(certs, crt)
	}

	return certs
}
