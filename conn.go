package tlslink

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/hashicorp/yamux"
)

type Conn struct {
	RemoteAddr net.Addr

	socket  *tls.Conn
	session *yamux.Session

	server   *Server
	identity string
	csr      []byte
}

func (c *Conn) Authorize() error {
	if c.server == nil {
		return fmt.Errorf("no server is available")
	}
	return c.server.Authorize(c)
}

func (c *Conn) GetIdentity(ident interface{}) error {
	return json.Unmarshal([]byte(c.identity), ident)
}

func (c *Conn) Close() {
	c.socket.Close()
}

func (c *Conn) Upgrade() *UpgradedConn {
	u := UpgradedConn{
		Conn: *c,
	}

	// Create a http client that uses our multiplexed connection
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return u.session.Open()
		},
	}
	u.client = &http.Client{Transport: tr}

	return &u
}

type UpgradedConn struct {
	Conn

	client *http.Client
}

func (c *UpgradedConn) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}
