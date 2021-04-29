package ca

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
)

const storagePath = "certificates"

type CA struct {
	namespace string

	X509   map[string]*x509.Certificate
	TLS    map[string]*tls.Certificate
	CAX509 *x509.Certificate
	CATLS  *tls.Certificate
	CAFile []byte
	SANs   string
	path   string

	sync.Mutex
}

func New(namespace, SANs, path string) (*CA, error) {
	ca := &CA{
		namespace: namespace,
		X509:      make(map[string]*x509.Certificate),
		TLS:       make(map[string]*tls.Certificate),
		SANs:      SANs,
		path:      path,
	}

	err := ca.LoadOrCreate("ca")
	if err != nil {
		return nil, err
	}

	return ca, nil
}
