package nebula

import (
	"io"
	"math/rand"
	"net"
	"reflect"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

type fwd struct {
	addr    string   // listening port
	targets []string // forward target
}

var forwardServers []*ForwardServer
var forwardMapping []*fwd

func forwardMain(l *logrus.Logger, ipn *net.IPNet, c *config.C) func() {
	c.RegisterReloadCallback(func(c *config.C) {
		reloadForward(l, ipn, c)
	})

	return func() {
		startForward(l, ipn, c)
	}
}

func reloadForward(l *logrus.Logger, ipn *net.IPNet, c *config.C) {
	if reflect.DeepEqual(forwardMapping, getForwardMapping(l, ipn, c)) {
		l.Debug("No Forward server config change detected")
		return
	}

	l.Debug("Restarting Forward server")
	for _, s := range forwardServers {
		s.Shutdown()
	}
	forwardServers = nil
	go startForward(l, ipn, c)
}

func newFwd(ipn *net.IPNet, m map[interface{}]interface{}) *fwd {
	port, pok := m["port"].(int)
	address, aok := m["address"].(string)
	targets, tok := m["targets"].([]interface{})

	rtargets := make([]string, 0, len(targets))
	for _, t := range targets {
		if t, ok := t.(string); ok {
			rtargets = append(rtargets, t)
		}
	}
	if !aok {
		address = ipn.IP.String()
	}

	if pok && tok {
		return &fwd{
			addr:    address + ":" + strconv.Itoa(port),
			targets: rtargets,
		}
	}
	return nil
}

func getForwardMapping(l *logrus.Logger, ipn *net.IPNet, c *config.C) (fwds []*fwd) {
	f := c.Get("forward")
	switch f := f.(type) {
	case map[interface{}]interface{}:
		if fwd := newFwd(ipn, f); fwd != nil {
			fwds = append(fwds, fwd)
		}
	case []interface{}:
		for _, v := range f {
			m, ok := v.(map[interface{}]interface{})
			if ok {
				if fwd := newFwd(ipn, m); fwd != nil {
					fwds = append(fwds, fwd)
				}
			}
		}
	}
	return
}

func startForward(l *logrus.Logger, ipn *net.IPNet, c *config.C) {
	f := c.Get("forward")
	if f == nil {
		return
	}

	rand.Seed(time.Now().UnixNano())

	forwardMapping = getForwardMapping(l, ipn, c)
	if len(forwardMapping) == 0 {
		l.WithField("config", f).Error("Bad forward config")
	}

	for _, fwd := range forwardMapping {
		forwardServer := &ForwardServer{Addr: fwd.addr, logger: l, Targets: fwd.targets}
		l.WithFields(logrus.Fields{
			"forwardListener": fwd.addr,
			"targets":         fwd.targets,
		}).Infof("Starting Forward server")

		forwardServers = append(forwardServers, forwardServer)
		go func() {
			err := forwardServer.ListenAndServe()
			defer forwardServer.Shutdown()
			if err != nil {
				l.Errorf("Failed to start Forward server: %s\n ", err.Error())
			}
		}()
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
	if s.lis != nil {
		s.lis.Close()
	}
}

func (s *ForwardServer) ShuffledTargets() []string {
	targets := make([]string, len(s.Targets))
	copy(targets, s.Targets)
	rand.Shuffle(len(targets), func(i, j int) {
		targets[i], targets[j] = targets[j], targets[i]
	})
	return targets
}

func (s *ForwardServer) process(client net.Conn) {
	clientAddr := client.RemoteAddr().String()
	forwarded := false
	for _, target := range s.ShuffledTargets() {
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
