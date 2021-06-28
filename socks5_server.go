package nebula

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/sirupsen/logrus"
)

var socks5Server *Socks5Server
var socks5Addr string

func socks5Main(l *logrus.Logger, ipn *net.IPNet, c *Config) func() {
	c.RegisterReloadCallback(func(c *Config) {
		reloadSocks5(l, ipn, c)
	})

	return func() {
		startSocks5(l, ipn, c)
	}
}

func reloadSocks5(l *logrus.Logger, ipn *net.IPNet, c *Config) {
	if socks5Addr == getSocks5ServerAddr(ipn, c) {
		l.Debug("No SOCKS5 server config change detected")
		return
	}

	l.Debug("Restarting SOCKS5 server")
	socks5Server.Shutdown()
	go startSocks5(l, ipn, c)
}

func getSocks5ServerAddr(ipn *net.IPNet, c *Config) string {
	return ipn.IP.String() + ":" + c.GetString("socks5.port", "")
}

func startSocks5(l *logrus.Logger, ipn *net.IPNet, c *Config) {
	socks5Addr = getSocks5ServerAddr(ipn, c)
	socks5Server = &Socks5Server{Addr: socks5Addr, logger: l}
	l.WithField("socks5Listener", socks5Addr).Infof("Starting SOCKS5 server")
	err := socks5Server.ListenAndServe()
	defer socks5Server.Shutdown()
	if err != nil {
		l.Errorf("Failed to start SOCKS5 server: %s\n ", err.Error())
	}
}

// Socks5Server adapted from https://gist.github.com/felix021/7f9d05fa1fd9f8f62cbce9edbdb19253
type Socks5Server struct {
	logger *logrus.Logger
	lis    net.Listener
	Addr   string
}

func (s *Socks5Server) ListenAndServe() (err error) {
	s.lis, err = net.Listen("tcp", s.Addr)
	if err != nil {
		return
	}

	for {
		client, err := s.lis.Accept()
		if err != nil {
			s.logger.Debugf("accept failed: %v", err)
			continue
		}
		go s.process(client)
	}
}

func (s *Socks5Server) Shutdown() {
	s.lis.Close()
}

func (s *Socks5Server) process(client net.Conn) {
	clientAddr := client.RemoteAddr().String()
	if err := Socks5Auth(client); err != nil {
		s.logger.WithField("client", clientAddr).Debugf("auth error: %v", err)
		client.Close()
		return
	}

	target, err := Socks5Connect(client)
	if err != nil {
		s.logger.WithField("client", clientAddr).Debugf("connect error: %v", err)
		client.Close()
		return
	}

	Socks5Forward(client, target)
}

func Socks5Auth(client net.Conn) (err error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(client, buf[:2])
	if n != 2 {
		return errors.New("reading header: " + err.Error())
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	n, err = io.ReadFull(client, buf[:nMethods])
	if n != nMethods {
		return errors.New("reading methods: " + err.Error())
	}

	n, err = client.Write([]byte{0x05, 0x00})
	if n != 2 || err != nil {
		return errors.New("write rsp: " + err.Error())
	}

	return nil
}

func Socks5Connect(client net.Conn) (net.Conn, error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(client, buf[:4])
	if n != 4 {
		return nil, errors.New("read header: " + err.Error())
	}

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 || cmd != 1 {
		return nil, errors.New("invalid ver/cmd")
	}

	addr := "" // https://datatracker.ietf.org/doc/html/rfc1928#section-5
	switch atyp {
	case 1:
		n, err = io.ReadFull(client, buf[:4])
		if n != 4 {
			return nil, errors.New("invalid IPv4: " + err.Error())
		}
		addr = net.IP(buf[:4]).String()

	case 3:
		n, err = io.ReadFull(client, buf[:1])
		if n != 1 {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addrLen := int(buf[0])

		n, err = io.ReadFull(client, buf[:addrLen])
		if n != addrLen {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addr = string(buf[:addrLen])

	case 4:
		n, err = io.ReadFull(client, buf[:16])
		if n != 16 {
			return nil, errors.New("invalid IPv6: " + err.Error())
		}
		addr = "[" + net.IP(buf[:16]).String() + "]"

	default:
		return nil, errors.New("invalid atyp")
	}

	n, err = io.ReadFull(client, buf[:2])
	if n != 2 {
		return nil, errors.New("read port: " + err.Error())
	}
	port := binary.BigEndian.Uint16(buf[:2])

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		return nil, errors.New("dial dst: " + err.Error())
	}

	_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		dest.Close()
		return nil, errors.New("write rsp: " + err.Error())
	}

	return dest, nil
}

func Socks5Forward(client, target net.Conn) {
	forward := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		io.Copy(src, dest)
	}
	go forward(client, target)
	go forward(target, client)
}
