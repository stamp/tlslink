package main

import (
	"io/ioutil"
	"net/http"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stamp/tlslink"
)

type Identity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func main() {
	rServer := gin.Default()
	rServer.GET("/test-server", func(c *gin.Context) {
		c.String(200, "test-client answer")
	})

	server, err := tlslink.NewServer("tls-link", "./server-certs")
	if err != nil {
		logrus.Fatal(err)
	}

	server.SetHandler(rServer)

	server.HandleRegistration(func(c *tlslink.Conn) error {
		err := c.Authorize()
		if err != nil {
			return err
		}
		identity := &Identity{}
		c.GetIdentity(identity)
		spew.Dump(identity)

		logrus.Printf("Server: Client %s registered", c.RemoteAddr)
		return nil
	})
	server.HandleConnect(func(c *tlslink.UpgradedConn) error {
		identity := &Identity{}
		c.GetIdentity(identity)
		spew.Dump(identity)

		logrus.Printf("Server: Client %s authorized", c.RemoteAddr)

		req, _ := http.NewRequest("GET", "http://example.com/test-client", nil)
		for i := 0; i < 10; i++ {
			go func() {
				_, err := c.Do(req)
				if err != nil {
					logrus.Error(err)
					return
				}
			}()
		}
		return nil
	})
	server.HandleDisconnect(func(c *tlslink.Conn) error {
		identity := &Identity{}
		c.GetIdentity(identity)
		spew.Dump(identity)

		logrus.Printf("Server: Client %s disconnected", c.RemoteAddr)
		return nil
	})

	go func() {
		<-time.After(time.Second * 3)
		logrus.Info("server is listening")
		server.ListenAndServe("localhost:33333")
	}()

	// -------------------------------------------------

	rClient := gin.Default()
	rClient.GET("/test-client", func(c *gin.Context) {
		c.String(200, "test-client answer")
	})

	identity := Identity{
		Name:    "demo client",
		Version: "1.2.3",
	}
	client, err := tlslink.NewClient("tls-link", identity, "./client-certs")
	if err != nil {
		logrus.Fatal(err)
	}

	client.SetHandler(rClient)

	client.HandleRegistration(func(c *tlslink.Conn) error {
		logrus.Printf("Client: Was registered to server %s", c.RemoteAddr)
		return nil
	})
	client.HandleConnect(func(c *tlslink.UpgradedConn) error {
		logrus.Printf("Client: Was connected to server %s", c.RemoteAddr)

		req, err := http.NewRequest("GET", "http://example.com/test-server", nil)
		resp, err := c.Do(req)
		body, _ := ioutil.ReadAll(resp.Body)
		spew.Dump(body, err)
		<-time.After(time.Second * 5)

		c.Close()
		return nil
	})
	client.HandleDisconnect(func(c *tlslink.Conn) error {
		logrus.Printf("Client: Was disconnected from server %s", c.RemoteAddr)
		return nil
	})

	go func() {
		for {
			err := client.DialAndWait("localhost:33333")
			logrus.WithFields(logrus.Fields{
				"call": "client.Dial",
			}).Error(err)

			<-time.After(time.Second)
		}
	}()

	select {}
}
