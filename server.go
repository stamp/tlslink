package tlslink

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"sync"

	"github.com/hashicorp/yamux"
	"github.com/sirupsen/logrus"
	"github.com/stamp/tlslink/ca"
)

type Server struct {
	namespace string
	tlsConfig *tls.Config
	ca        *ca.CA

	handler           http.Handler
	regHandler        ServerRegistrationHandler
	connectHandler    ServerConnectHandler
	disconnectHandler ServerDisconnectHandler

	sync.RWMutex
}

type TlsInfoMiddleware struct {
	handler http.Handler
	tls     *tls.ConnectionState
}

func (m *TlsInfoMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Append the TLS connection state
	r.TLS = m.tls
	m.handler.ServeHTTP(w, r)
}

type ServerRegistrationHandler func(*Conn) error
type ServerConnectHandler func(*UpgradedConn) error
type ServerDisconnectHandler func(*Conn) error

func NewServer(namespace, storage string, SANs ...string) (*Server, error) {
	var err error

	s := &Server{
		namespace: namespace,
	}

	s.ca, err = ca.New(namespace, storage, SANs...)
	if err != nil {
		return nil, err
	}

	// Get certificates
	s.tlsConfig, err = s.ca.GetTlsConfig()
	if err != nil {
		return nil, err
	}

	// Require a modern standard
	s.tlsConfig.MinVersion = tls.VersionTLS12
	s.tlsConfig.CurvePreferences = []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256}
	s.tlsConfig.PreferServerCipherSuites = true
	s.tlsConfig.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}

	return s, nil
}
func (s *Server) ListenAndServe(addr string) error {
	ln, err := tls.Listen("tcp", addr, s.tlsConfig)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			logrus.Error(err)
			continue
		}

		socket := conn.(*tls.Conn)

		err = socket.Handshake()
		if err != nil {
			logrus.Error(err)
			continue
		}

		//spew.Dump(conn.(*tls.Conn))
		if len(socket.ConnectionState().PeerCertificates) > 0 {
			go s.handleAuthorizedConnection(socket)
		} else {
			go s.handleUnsafeConnection(socket)
		}
	}
}

func (s *Server) Authorize(c *Conn, templateEnhancer ...func(template *x509.Certificate)) error {
	cert, err := s.ca.CreateCertificateFromRequest(c.csr, templateEnhancer...)
	if err != nil {
		return err
	}

	encoded := "CRT" + base64.StdEncoding.EncodeToString(cert) + "\n"
	_, err = c.socket.Write([]byte(encoded))
	if err != nil {
		return err
	}

	encoded = "CA " + base64.StdEncoding.EncodeToString(s.ca.CAFile) + "\n"
	_, err = c.socket.Write([]byte(encoded))
	if err != nil {
		return err
	}

	// Send the certs and disconnect
	c.socket.Close()

	return nil
}

func (s *Server) SetHandler(handler http.Handler) {
	s.Lock()
	defer s.Unlock()

	s.handler = handler
}
func (s *Server) HandleRegistration(fn ServerRegistrationHandler) {
	s.Lock()
	defer s.Unlock()

	s.regHandler = fn
}
func (s *Server) HandleConnect(fn ServerConnectHandler) {
	s.Lock()
	defer s.Unlock()

	s.connectHandler = fn
}
func (s *Server) HandleDisconnect(fn ServerDisconnectHandler) {
	s.Lock()
	defer s.Unlock()

	s.disconnectHandler = fn
}

func (s *Server) handleAuthorizedConnection(socket *tls.Conn) {
	defer socket.Close()

	logrus.WithFields(logrus.Fields{
		"call": "server: conn.Read",
	}).Info("New trusted connection")

	conn := &Conn{
		uuid:       socket.ConnectionState().PeerCertificates[0].Subject.CommonName,
		RemoteAddr: socket.RemoteAddr(),
		socket:     socket,
		server:     s,
	}

	r := bufio.NewReader(socket)
	msg, err := r.ReadString('\n')
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"call": "server: server.handleAuthorizedConnection",
		}).Error(err)
		return
	}

	if len(msg) < 3 {
		logrus.WithFields(logrus.Fields{
			"call": "server: server.handleAuthorizedConnection",
		}).Error("Received unknown message, disconnecting")
		return
	}

	data := msg[3:]
	if msg[0:3] != "ID " {
		logrus.WithFields(logrus.Fields{
			"call": "server: server.handleAuthorizedConnection",
		}).Error("Received unknown message, disconnecting")
		return
	}

	conn.identity = data

	// Startup the multiplexer
	conn.session, err = yamux.Server(socket, nil)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"call":  "server: HandleConnect",
			"error": err,
		}).Error("failed to start muliplexing, disconnecting")
		return
	}

	uconn := conn.Upgrade()

	// Notify that we are connected
	s.RLock()
	fn := s.connectHandler
	s.RUnlock()

	if fn != nil {
		err = fn(uconn)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"call":  "server: HandleConnect",
				"error": err,
			}).Error("connect handler failed, disconnecting")
			conn.Close()
			return
		}
	}

	defer func() {
		// Notify when connection is closed
		s.RLock()
		fn := s.disconnectHandler
		s.RUnlock()

		if fn != nil {
			err = fn(conn)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"call":  "server: HandleDisconnect",
					"error": err,
				}).Error("disconnect handler failed")
				return
			}
		}
	}()

	// Serve http over the multiplexed connection
	conState := socket.ConnectionState()
	s.RLock()
	handler := &TlsInfoMiddleware{
		handler: s.handler,
		tls:     &conState,
	}
	s.RUnlock()

	err = http.Serve(conn.session, handler)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"call":  "server: http.Serve",
			"error": err,
		}).Error("failed to serve http, disconnecting")
		return
	}
}

func (s *Server) handleUnsafeConnection(socket *tls.Conn) {
	defer socket.Close()

	logrus.WithFields(logrus.Fields{
		"call": "server: server.handleUnsafeConnection",
	}).Info("New untrusted connection")
	//spew.Dump(socket.ConnectionState())
	//printConnState(socket)

	conn := &Conn{
		RemoteAddr: socket.RemoteAddr(),
		socket:     socket,
		server:     s,
	}

	r := bufio.NewReader(socket)
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"call": "server: conn.Read",
			}).Error(err)
			return
		}

		if len(msg) < 3 {
			logrus.WithFields(logrus.Fields{
				"call": "server: conn.Read",
			}).Error("Received unknown message, disconnecting")
			return
		}

		data := msg[3:]
		switch msg[0:3] {
		case "ID ":
			conn.identity = data
		case "CSR":
			conn.csr, err = base64.StdEncoding.DecodeString(data)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"call": "server: conn.handleUnsafeConnection",
				}).Error("could not decode CSR, disconnecting")
				return
			}

			block, _ := pem.Decode(conn.csr)
			req, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"call": "server: conn.handleUnsafeConnection",
				}).Error("could not parse CSR, disconnecting")
				return
			}
			conn.uuid = req.Subject.CommonName

			s.RLock()
			fn := s.regHandler
			s.RUnlock()

			if fn != nil {
				err = fn(conn)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"call":  "server: HandleRegistation",
						"error": err,
					}).Error("registration handler failed, disconnecting")
					return
				}
			}

			defer func() {
				// Notify when connection is closed
				s.RLock()
				fn := s.disconnectHandler
				s.RUnlock()

				if fn != nil {
					err = fn(conn)
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"call":  "server: HandleDisconnect",
							"error": err,
						}).Error("connect handler failed, disconnecting")
						return
					}
				}
			}()
		}
	}
}
