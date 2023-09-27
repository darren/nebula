package nebula

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

var proxyServer *Proxy
var proxyAddr string

func proxyMain(l *logrus.Logger, ipn *net.IPNet, c *config.C) func() {
	c.RegisterReloadCallback(func(c *config.C) {
		reloadProxy(l, ipn, c)
	})

	return func() {
		startProxy(l, ipn, c)
	}
}

func reloadProxy(l *logrus.Logger, ipn *net.IPNet, c *config.C) {
	if proxyAddr == getProxyServerAddr(ipn, c) {
		l.Debug("No Proxy server config change detected")
		return
	}

	l.Debug("Restarting Proxy server")
	proxyServer.Shutdown()
	go startProxy(l, ipn, c)
}

func getProxyServerAddr(ipn *net.IPNet, c *config.C) string {
	return ipn.IP.String() + ":" + c.GetString("socks5.port", "")
}

func startProxy(l *logrus.Logger, ipn *net.IPNet, c *config.C) {
	proxyAddr = getProxyServerAddr(ipn, c)
	proxyServer = &Proxy{Addr: proxyAddr, logger: l}
	l.WithField("proxyListener", proxyAddr).Infof("Starting Proxy server")
	err := proxyServer.ListenAndServe()
	defer proxyServer.Shutdown()
	if err != nil {
		l.Errorf("Failed to start proxy server: %s\n ", err.Error())
	}
}

// Proxy adapted from https://gist.github.com/felix021/7f9d05fa1fd9f8f62cbce9edbdb19253
type Proxy struct {
	logger *logrus.Logger
	lis    net.Listener
	Addr   string
}

func (s *Proxy) ListenAndServe() (err error) {
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

func (s *Proxy) Shutdown() {
	s.lis.Close()
}

func (s *Proxy) process(client net.Conn) {
	clientAddr := client.RemoteAddr().String()

	handshake := make([]byte, 2)
	n, err := io.ReadFull(client, handshake[:2])
	if n != 2 {
		s.logger.WithField("client", clientAddr).Debugf("detector: %v", err)
		return
	}

	if bytes.Equal(handshake, []byte("GE")) { // HTTP GET
		r := bufio.NewReader(io.MultiReader(bytes.NewReader(handshake), client))
		req, err := http.ReadRequest(r)
		if err != nil {
			s.logger.WithField("client", clientAddr).Debugf("http read error: %v", err)
			client.Close()
			return
		}

		req.RequestURI = ""
		prune(req.Header)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.logger.WithField("client", clientAddr).Debugf("http forward error: %v", err)
			client.Close()
			return
		}

		resp.Write(client)
		client.Close()

	} else if bytes.Equal(handshake, []byte("CO")) { // HTTP CONNECT
		r := bufio.NewReader(io.MultiReader(bytes.NewReader(handshake), client))
		req, err := http.ReadRequest(r)
		if err != nil {
			s.logger.WithField("client", clientAddr).Debugf("http read error: %v", err)
			client.Close()
			return
		}

		target, err := net.Dial("tcp", req.Host)
		if err != nil {
			io.WriteString(client, "HTTP/1.1 500\r\n")
			io.WriteString(client, err.Error())
			io.WriteString(client, "\r\n\r\n")
			client.Close()
			return
		}

		req.Body.Close()
		io.WriteString(client, "HTTP/1.1 200  Connection established\r\n\r\n")
		ProxyForward(client, target)

	} else {
		if err := Socks5Auth(handshake, client); err != nil {
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

		ProxyForward(client, target)
	}
}

func Socks5Auth(handshake []byte, client net.Conn) (err error) {
	buf := make([]byte, 256)

	ver, nMethods := int(handshake[0]), int(handshake[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	n, err := io.ReadFull(client, buf[:nMethods])
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

func ProxyForward(client, target net.Conn) {
	forward := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		io.Copy(src, dest)
	}
	go forward(client, target)
	go forward(target, client)
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// removeConnectionHeaders removes hop-by-hop headers listed in the "Connection" header of h.
// See RFC 7230, section 6.1
func removeConnectionHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
}

func removeHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		hv := h.Get(k)
		if hv == "" {
			continue
		}
		if k == "Te" && hv == "trailers" {
			continue
		}
		h.Del(k)
	}
}

// prune clean http header
func prune(h http.Header) {
	removeConnectionHeaders(h)
	removeHopHeaders(h)
}
