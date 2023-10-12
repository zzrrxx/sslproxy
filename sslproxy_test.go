package sslproxy

import (
	"os"
	"testing"
)

var cfg = &Config{
	LocalAddr: ":12345",
	CertFile: "D:\\Github\\go\\src\\sslproxy\\certs\\sslproxy.crt",
	KeyFile: "D:\\Github\\go\\src\\sslproxy\\certs\\sslproxy.key",
	OnSSLData: func(outgoing bool, localAddr string, remoteAddr string, data []byte) {
		if outgoing {
			println(localAddr + " -> " + remoteAddr + ": ")
		} else {
			println(localAddr + " <- " + remoteAddr + ": ")
		}

		println(ToHexDump(data))
	},
}

func TestSSLProxy_GenFakeCert(t *testing.T) {
	//cert, _ := os.ReadFile("cert.der")
	//certData, keyData, err := GenFakeCert(cert)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//os.WriteFile("fake.cer", certData, os.ModePerm)
	//os.WriteFile("fake.key", keyData, os.ModePerm)
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
