package sslproxy

import (
	"encoding/hex"
	"testing"
)

var cfg = &Config{
	LocalAddr: ":12345",
	CertFile: "D:\\Github\\go\\src\\sslproxy\\certs\\sslproxy.crt",
	KeyFile: "D:\\Github\\go\\src\\sslproxy\\certs\\sslproxy.key",
	OnSSLData: func(outgoing bool, localAddr string, remoteAddr string, data []byte) {
		if outgoing {
			println(localAddr + " -> " + remoteAddr + ": " + hex.EncodeToString(data))
		} else {
			println(localAddr + " <- " + remoteAddr + ": " + hex.EncodeToString(data))
		}
	},
}

func TestSSLProxy_Start(t *testing.T) {
	p := NewSSLProxy(cfg)
	err := p.Start()
	if err != nil {
		t.Fatal(err.Error())
	}
	defer func() {
		p.Stop()
	}()

	for {

	}

}
