package tlslink

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/common-nighthawk/go-figure"
	"github.com/sirupsen/logrus"
	"github.com/wolfeidau/humanhash"
)

func generateCSR(namespace, id, storage string) ([]byte, error) {
	subj := pkix.Name{
		CommonName:   id,
		Organization: []string{namespace},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	priv, err := loadOrGenerateKey(namespace, storage)
	if err != nil {
		return nil, err
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	d := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// Make a human readable string of the signature hash
	req, _ := x509.ParseCertificateRequest(csrBytes)
	result, _ := humanhash.Humanize(req.Signature, 2)
	myFigure := figure.NewFigure(result, "", true)

	fmt.Println("")
	myFigure.Print()
	fmt.Println("")
	fmt.Println("")
	fmt.Println(result)

	return d, nil
}

func loadOrGenerateKey(id, storage string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path.Join(storage, id+".key"))
	if err != nil {
		if os.IsNotExist(err) {
			return generateKey(id, storage)
		}
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func generateKey(id, storage string) (*rsa.PrivateKey, error) {
	os.MkdirAll(storage, 0700)

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyOut, err := os.OpenFile(path.Join(storage, id+".key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	logrus.Infof("link: created private.key")
	return priv, err
}
