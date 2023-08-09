package tlslink

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/gofrs/uuid"
	"github.com/hashicorp/yamux"
	"github.com/sirupsen/logrus"
)

type Client struct {
	namespace string
	storage   string
	conn      *tls.Conn
	identity  interface{}
	csr       []byte

	id        string
	x509      *x509.Certificate
	tls       *tls.Certificate
	ca        *x509.CertPool
	tlsConfig *tls.Config

	handler           http.Handler
	regHandler        ClientRegistrationHandler
	connectHandler    ClientConnectHandler
	disconnectHandler ClientDisconnectHandler

	sync.RWMutex
}

type ClientRegistrationHandler func(*Conn) error
type ClientConnectHandler func(*UpgradedConn) error
type ClientDisconnectHandler func(*Conn, error) error
type IDSettable interface {
	SetID(string)
}

func NewClient(namespace string, identity interface{}, storage string) (*Client, error) {
	c := &Client{
		namespace: namespace,
		storage:   storage,
		identity:  identity,
	}

	c.tlsConfig = &tls.Config{
		InsecureSkipVerify: true,

		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	// Try to load certificates, else generate a CSR
	err := c.loadCertificates()
	if err != nil {
		logrus.Warn("No client certificate available, generating a new CSR")
		id, err := uuid.NewV4()
		if err != nil {
			return nil, err
		}

		c.id = id.String()

		c.csr, err = generateCSR(namespace, id.String(), storage)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *Client) DialAndWait(addr string) error {
	var err error

	if id, ok := c.identity.(IDSettable); ok {
		id.SetID(c.id)
	}

	ident, err := json.Marshal(c.identity)
	if err != nil {
		return err
	}

	// Dial the other end
	c.conn, err = tls.Dial("tcp", addr, c.tlsConfig)
	if err != nil {
		return err
	}

	conn := &Conn{
		RemoteAddr: c.conn.RemoteAddr(),
		socket:     c.conn,
	}

	// Make sure to send our identity
	c.conn.Write([]byte("ID "))
	c.conn.Write(ident)
	c.conn.Write([]byte("\n"))
	logrus.Debug("Client: send ident: " + string(ident))

	// We are not authorized, make sure to initialize the csr exchange
	if c.tls == nil {
		err = c.exchangeCSR()
		if err != nil {
			c.conn.Close()
			return err
		}

		// Reconnect with the new certificates
		return c.DialAndWait(addr)
	}

	// Startup the multiplexer
	conn.session, err = yamux.Client(c.conn, nil)
	if err != nil {
		return err
	}

	uconn := conn.Upgrade()

	// Tell the parent that we have successfully connected
	c.RLock()
	fn := c.connectHandler
	c.RUnlock()

	if fn != nil {
		go func() {
			err = fn(uconn)
			if err != nil {
				//logrus.WithFields(logrus.Fields{
				//"call":  "client: HandleConnect",
				//"error": err,
				//}).Error("connect handler failed, disconnecting")
				c.conn.Close()
				return
			}
		}()
	}

	defer func() {
		if err != nil && strings.Contains(err.Error(), "bad certificate") {
			errx := c.clearCertificates()
			if errx != nil {
				logrus.WithFields(logrus.Fields{
					"error": errx,
				}).Error("Failed to clear invalid certificates")
			}
		}

		// Notify when connection is closed
		c.RLock()
		fn := c.disconnectHandler
		c.RUnlock()
		if fn != nil {
			errx := fn(conn, err)
			if errx != nil {
				//logrus.WithFields(logrus.Fields{
				//"call":  "client: HandleDisconnect",
				//"error": err,
				//}).Error("connect handler failed, disconnecting")
				return
			}
		}
	}()

	// Serve http over the multiplexed connection
	c.RLock()
	handler := c.handler
	c.RUnlock()

	err = http.Serve(conn.session, handler)
	if err != nil {
		//logrus.WithFields(logrus.Fields{
		//"call":  "client: http.Serve",
		//"error": err,
		//}).Error("failed to serve http, disconnecting")
		return nil
	}

	return nil
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) SetHandler(handler http.Handler) {
	c.Lock()
	defer c.Unlock()

	c.handler = handler
}
func (c *Client) HandleRegistration(fn ClientRegistrationHandler) {
	c.Lock()
	defer c.Unlock()

	c.regHandler = fn
}
func (c *Client) HandleConnect(fn ClientConnectHandler) {
	c.Lock()
	defer c.Unlock()

	c.connectHandler = fn
}
func (c *Client) HandleDisconnect(fn ClientDisconnectHandler) {
	c.Lock()
	defer c.Unlock()

	c.disconnectHandler = fn
}
func (c *Client) GetCertificate() *x509.Certificate {
	c.RLock()
	defer c.RUnlock()

	if c.x509 == nil {
		return nil
	}

	// Make a copy and return a pointer to it
	crt := *c.x509
	return &crt
}

func (c *Client) GetUUID() string {
	c.RLock()
	defer c.RUnlock()

	return c.id
}

// --------------------------------------------------------------------

func (c *Client) loadCertificates() error {
	os.MkdirAll(c.storage, 0700)
	filename := path.Join(c.storage, c.namespace)

	// Load CA cert
	caCert, err := ioutil.ReadFile(filename + ".ca.crt")
	if err != nil {
		return err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	c.ca = caCertPool

	c.tlsConfig.RootCAs = c.ca
	c.tlsConfig.InsecureSkipVerify = false

	// Load client cert
	certTLS, err := tls.LoadX509KeyPair(filename+".crt", filename+".key")
	if err != nil {
		return err
	}
	certX509, err := x509.ParseCertificate(certTLS.Certificate[0])
	if err != nil {
		return err
	}

	c.id = certX509.Subject.CommonName
	c.tls = &certTLS
	c.x509 = certX509
	c.tlsConfig.Certificates = []tls.Certificate{certTLS}

	return nil
}

func (c *Client) writeCertificates(certs map[string][]byte) error {
	os.MkdirAll(c.storage, 0700)

	for k, v := range certs {
		filename := ""

		switch k {
		case "CA ":
			filename = path.Join(c.storage, c.namespace+".ca.crt")
		case "CRT":
			filename = path.Join(c.storage, c.namespace+".crt")
		default:
			logrus.Errorf("unknown cert type '%s'", k)
			continue
		}

		err := ioutil.WriteFile(filename, v, 0600)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) clearCertificates() error {
	err := os.Remove(path.Join(c.storage, c.namespace+".crt"))
	if err != nil {
		return err
	}

	err = os.Remove(path.Join(c.storage, c.namespace+".key"))
	if err != nil {
		return err
	}

	c.id = ""
	c.tls = nil
	c.x509 = nil
	c.tlsConfig.Certificates = []tls.Certificate{}

	logrus.Warn("No client certificate available, generating a new CSR")
	id, err := uuid.NewV4()
	if err != nil {
		return err
	}

	c.id = id.String()

	c.csr, err = generateCSR(c.namespace, id.String(), c.storage)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) exchangeCSR() error {
	// Send the CSR
	c.conn.Write([]byte("CSR" + base64.StdEncoding.EncodeToString(c.csr) + "\n"))

	r := bufio.NewReader(c.conn)
	certs := make(map[string][]byte)
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"call": "client: client.exchangeCSR",
			}).Debug(err)
			return err
		}

		if len(msg) < 3 {
			logrus.WithFields(logrus.Fields{
				"call": "client: client.exchangeCSR",
			}).Debug("response is to short")
			return fmt.Errorf("response is to short")
		}

		decoded, err := base64.StdEncoding.DecodeString(msg[3:])
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"call": "client: client.exchangeCSR",
			}).Debug("could not decode certificate, disconnecting")
			return err
		}

		certs[msg[0:3]] = decoded

		_, crtOk := certs["CRT"]
		_, caOk := certs["CA "]

		if crtOk && caOk {
			logrus.Debug("Got all certs", crtOk, caOk)
			break
		}
	}

	err := c.writeCertificates(certs)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"call": "client: client.exchangeCSR",
		}).Debug("failed to save received certificates")
		return err
	}

	err = c.loadCertificates()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"call": "client: client.exchangeCSR",
		}).Debug("failed to read certificates")
		return err
	}

	return nil
}
