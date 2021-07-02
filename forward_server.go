package nebula

import (
	"io"
	"net"
	"reflect"

	"github.com/sirupsen/logrus"
)

var forwardServer *ForwardServer
var forwardAddr string
var forwardTargets []string

func forwardMain(l *logrus.Logger, ipn *net.IPNet, c *Config) func() {
	c.RegisterReloadCallback(func(c *Config) {
		reloadForward(l, ipn, c)
	})

	return func() {
		startForward(l, ipn, c)
	}
}

func reloadForward(l *logrus.Logger, ipn *net.IPNet, c *Config) {
	if forwardAddr == getForwardServerAddr(ipn, c) &&
		reflect.DeepEqual(forwardTargets, getForwardTargets(c)) {
		l.Debug("No Forward server config change detected")
		return
	}

	l.Debug("Restarting SOCKS5 server")
	forwardServer.Shutdown()
	go startForward(l, ipn, c)
}

func getForwardServerAddr(ipn *net.IPNet, c *Config) string {
	return ipn.IP.String() + ":" + c.GetString("forward.port", "")
}

func getForwardTargets(c *Config) []string {
	return c.GetStringSlice("forward.targets", nil)
}

func startForward(l *logrus.Logger, ipn *net.IPNet, c *Config) {
	forwardAddr = getForwardServerAddr(ipn, c)
	forwardTargets = getForwardTargets(c)
	forwardServer = &ForwardServer{Addr: forwardAddr, logger: l, Targets: forwardTargets}
	l.WithFields(logrus.Fields{
		"forwardListener": forwardAddr,
		"targets":         forwardTargets,
	}).Infof("Starting Forward server")

	err := forwardServer.ListenAndServe()
	defer forwardServer.Shutdown()
	if err != nil {
		l.Errorf("Failed to start Forward server: %s\n ", err.Error())
	}
}

// ForwardSerer redirects connection to remote targets
type ForwardServer struct {
	Addr    string
	logger  *logrus.Logger
	lis     net.Listener
	Targets []string
}

func (s *ForwardServer) ListenAndServe() (err error) {
	s.lis, err = net.Listen("tcp", s.Addr)
	if err != nil {
		return
	}

	for {
		client, err := s.lis.Accept()
		if err != nil {
			s.logger.Debugf("forward accept failed: %v", err)
			continue
		}
		go s.process(client)
	}
}

func (s *ForwardServer) Shutdown() {
	s.lis.Close()
}

func (s *ForwardServer) process(client net.Conn) {
	clientAddr := client.RemoteAddr().String()
	forwarded := false
	for _, target := range s.Targets {
		conn, err := net.Dial("tcp", target)
		if err == nil {
			forwarded = true
			tcpForward(client, conn)
			break
		} else {
			s.logger.WithField("client", clientAddr).Debugf("forward to %s failed: %v", target, err)
		}
	}
	if !forwarded {
		client.Close()
	}
}

func tcpForward(client, target net.Conn) {
	forward := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		io.Copy(src, dest)
	}
	go forward(client, target)
	go forward(target, client)
}
