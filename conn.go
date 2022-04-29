package tlslink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/hashicorp/yamux"
	"github.com/sirupsen/logrus"
	"github.com/wolfeidau/humanhash"
)

type Conn struct {
	RemoteAddr net.Addr

	socket  *tls.Conn
	session *yamux.Session

	server   *Server
	uuid     string
	identity string
	csr      []byte

	sync.Mutex
}

func (c *Conn) Authorize() error {
	if c.server == nil {
		return fmt.Errorf("no server is available")
	}
	return c.server.Authorize(c)
}

func (c *Conn) GetUUID() string {
	return c.uuid
}

func (c *Conn) GetIdentity(ident interface{}) error {
	return json.Unmarshal([]byte(c.identity), ident)
}

func (c *Conn) GetCSR() []byte {
	return c.csr
}

func (c *Conn) GetCsrSignature() string {
	csr := c.GetCSR()

	block, _ := pem.Decode(csr)
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		fmt.Println(string(csr))
		logrus.Warn(err)
		return ""
	}

	signature, err := humanhash.Humanize(req.Signature, 2)
	if err != nil {
		logrus.Warn(err)
		return ""
	}

	return signature
}

func (c *Conn) Close() {
	c.socket.Close()
}

func (c *Conn) Upgrade() *UpgradedConn {
	u := UpgradedConn{
		Conn: *c,
	}

	// Create a http client that uses our multiplexed connection
	u.transport = &http.Transport{
		DisableKeepAlives: false, // Dont disable keep-alive (needed for websockets)
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return u.session.Open()
		},
	}
	u.client = &http.Client{Transport: u.transport}

	return &u
}

// ---------------------------------------------------------------------

type UpgradedConn struct {
	Conn

	transport *http.Transport
	client    *http.Client
}

func (c *UpgradedConn) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

func (c *UpgradedConn) GetTransport() *http.Transport {
	return c.transport
}
