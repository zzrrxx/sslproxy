package sslproxy

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

type Config struct {
	LocalAddr string

	OnSSLData func(outgoing bool, localAddr string, remoteAddr string, data []byte)
}

type SSLProxy struct {
	Cfg *Config

	listener net.Listener
	mu sync.Mutex
	fakeCerts map[string]*tls.Certificate
}

func NewSSLProxy(cfg *Config) *SSLProxy {
	return &SSLProxy{
		Cfg: cfg,
		fakeCerts: make(map[string]*tls.Certificate),
	}
}

func (p *SSLProxy) Start() error {
	log.Println("Starting")
	ln, err := net.Listen("tcp", p.Cfg.LocalAddr)
	if err != nil {
		log.Println(err.Error())
		return err
	}
	p.listener = ln
	go p.acceptConns()
	log.Println("Started")
	log.Printf("Listening on: %s\n", ln.Addr().String())
	return nil
}
func (p *SSLProxy) Stop() error {
	if p.listener != nil {
		if err := p.listener.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (p *SSLProxy) acceptConns() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go p.handleConn(conn)
	}
}
func (p *SSLProxy) handleConn(conn net.Conn) {
	log.Printf("[%s]New connection incoming\n", conn.RemoteAddr().String())
	var (
		outConn net.Conn
		target = ""
		err error
	)

	target, err = p.httpProxyHandshake(conn)
	if err != nil {
		log.Printf("[%s]Proxy handshake failed: %s\n", conn.RemoteAddr().String(), err.Error())
		goto done
	}
	log.Printf("[%s]Proxy handshake done\n", conn.RemoteAddr().String())

	outConn, err = p.connectToRemote(target)
	if err != nil {
		log.Printf("[%s]Connect to remote failed: %s %s\n", conn.RemoteAddr().String(), target, err.Error())
		goto done
	}
	log.Printf("[%s]Connect to remote successfully: %s\n", conn.RemoteAddr().String(), target)

	if err = p.proxy(conn, outConn); err != nil {
		log.Printf("[%s]Proxy connection failed: %s %s\n", conn.RemoteAddr().String(), target, err.Error())
		goto done
	}

done:
	conn.Close()
	if outConn != nil {
		outConn.Close()
	}
	log.Printf("[%s]Close connection\n", conn.RemoteAddr().String())
}

func (p *SSLProxy) httpProxyHandshake(conn net.Conn) (target string, err error) {
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	line, err := rw.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.Trim(line, "\r\n")
	parts := strings.Split(line, " ")
	if len(parts) != 3 || parts[0] != "CONNECT" || parts[2] != "HTTP/1.1" {
		err = errors.New("invalid http proxy connect request")
		return
	}
	target = parts[1]

	// consume all subsequence http content
	for {
		if line, err = rw.ReadString('\n'); err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}

	_, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		return
	}

	err = rw.Flush()
	return
}
func (p *SSLProxy) connectToRemote(target string) (net.Conn, error) {
	return net.Dial("tcp", target)
}
func (p *SSLProxy) proxy(inConn, outConn net.Conn) error {
	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	outTlsCon := tls.Client(outConn, tlsClientConfig)
	if err := outTlsCon.Handshake(); err != nil {
		log.Printf("[%s]TLS handshake with the remote server failed: %s\n", inConn.RemoteAddr().String(), err.Error())
		return err
	}

	realServerCert := outTlsCon.ConnectionState().PeerCertificates[0]
	fakeCert, err := p.genFakeCert(realServerCert.Raw)
	if err != nil {
		log.Printf("[%s]TLS handshake with the incoming connection failed: %s\n", inConn.RemoteAddr().String(), err.Error())
		return err
	}

	tlsServerConfig := &tls.Config{
		Certificates:                []tls.Certificate{*fakeCert},
		InsecureSkipVerify:          true,
	}
	inTlsCon := tls.Server(inConn, tlsServerConfig)
	if err := inTlsCon.Handshake(); err != nil {
		log.Printf("[%s]TLS handshake with the incoming connection failed: %s\n", inConn.RemoteAddr().String(), err.Error())
		return err
	}

	for {
		if err := p.proxyLocalDataIn(inTlsCon, outTlsCon); err != nil {
			return err
		}
		if err := p.proxyRemoteDataIn(inTlsCon, outTlsCon); err != nil {
			return err
		}
	}

	return nil
}
func (p *SSLProxy) proxyLocalDataIn(inConn, outConn net.Conn) error {
	data, err := p.tryRead(inConn, 20)
	if err != nil {
		log.Printf("[%s]Read from the incoming connection failed: %s\n", inConn.RemoteAddr().String(), err.Error())
		return err
	}
	if len(data) > 0 {
		if p.Cfg.OnSSLData != nil {
			p.Cfg.OnSSLData(true, inConn.RemoteAddr().String(), outConn.RemoteAddr().String(), data)
		}
		if err := p.mustWrite(outConn, data); err != nil {
			log.Printf("[%s]Write to server failed: %s\n", inConn.RemoteAddr().String(), err.Error())
			return err
		}
	}
	return nil
}
func (p *SSLProxy) proxyRemoteDataIn(inConn, outConn net.Conn) error {
	data, err := p.tryRead(outConn, 20)
	if err != nil {
		log.Printf("[%s]Read from the remote server failed: %s\n", inConn.RemoteAddr().String(), err.Error())
		return err
	}
	if len(data) > 0 {
		if p.Cfg.OnSSLData != nil {
			p.Cfg.OnSSLData(false, inConn.RemoteAddr().String(), outConn.RemoteAddr().String(), data)
		}
		if err = p.mustWrite(inConn, data); err != nil {
			log.Printf("[%s]Write to local connection failed: %s\n", inConn.RemoteAddr().String(), err.Error())
			return err
		}
	}
	return nil
}
func (p *SSLProxy) tryRead(conn net.Conn, timeoutMS int) ([]byte, error) {
	inBuf := make([]byte, 65536)
	conn.SetReadDeadline(time.Now().Add(time.Millisecond * time.Duration(timeoutMS)))
	inLen, err := conn.Read(inBuf)
	if inLen > 0 {
		return inBuf[:inLen], nil
	}
	if p.isOpErrorTimeout(err) {
		return []byte{}, nil
	}
	return nil, err
}
func (p *SSLProxy) mustWrite(conn net.Conn, data []byte) error {
	total := len(data)
	offset := 0
	for offset < total {
		outLen, err := conn.Write(data[offset:total])
		if outLen > 0 {
			offset += outLen
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (p *SSLProxy) isOpErrorTimeout(err error) bool {
	if err != nil {
		if operr, ok := err.(*net.OpError); ok {
			if operr.Timeout() {
				return true
			}
		}
	}
	return false
}

func (p *SSLProxy) genFakeCert(certData []byte) (*tls.Certificate, error) {
	cc := p.findCertInCache(certData)
	if cc != nil { // cached cert
		return cc, nil
	}

	fakeCert, fakeKey, err := GenFakeCert(certData)
	if err != nil {
		return nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Bytes:   fakeCert,
	})
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY",
		Bytes: fakeKey,
	})

	c, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	p.cacheCert(certData, &c)
	return &c, nil
}
func (p *SSLProxy) findCertInCache(certData []byte) *tls.Certificate {
	p.mu.Lock()
	defer p.mu.Unlock()

	certId := hex.EncodeToString(certData)
	if c, ok := p.fakeCerts[certId]; ok {
		return c
	}
	return nil
}
func (p *SSLProxy) cacheCert(certData []byte, c *tls.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()

	certId := hex.EncodeToString(certData)
	p.fakeCerts[certId] = c
}