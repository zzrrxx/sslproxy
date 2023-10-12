package sslproxy

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func GenFakeCert(certData []byte) ([]byte, []byte, error) {
	var (
		fakePubKey any
		fakePrivKeyData []byte
	)

	parentCert := loadCACert()
	parentKey  := loadCAKey()

	tempCert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, nil, err
	}

	switch tempPubKey := tempCert.PublicKey.(type) {
	case *rsa.PublicKey:
		// 2048 takes longer time, so use 1024 instead
		if pk, err := rsa.GenerateKey(rand.Reader, 1024); err != nil {
			return nil, nil, err
		} else {
			fakePubKey = &pk.PublicKey
			fakePrivKeyData, err = x509.MarshalPKCS8PrivateKey(pk)
			if err != nil {
				return nil, nil, err
			}
		}
	case *ecdsa.PublicKey:
		if pk, err := ecdsa.GenerateKey(tempPubKey.Curve, rand.Reader); err != nil {
			return nil, nil, err
		} else {
			fakePubKey = &pk.PublicKey
			fakePrivKeyData, err = x509.MarshalPKCS8PrivateKey(pk)
			if err != nil {
				return nil, nil, err
			}
		}
	case ed25519.PublicKey:
		if pubKey, privKey, err := ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, nil, err
		} else {
			fakePubKey = &pubKey
			fakePrivKeyData, err = x509.MarshalPKCS8PrivateKey(privKey)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	fakeCert, err := x509.CreateCertificate(rand.Reader, tempCert, parentCert, fakePubKey, parentKey)
	if err != nil {
		return nil, nil, err
	}

	return fakeCert, fakePrivKeyData, nil
}

func loadCACert() *x509.Certificate {
	caCertData := `-----BEGIN CERTIFICATE-----
MIIEHjCCAwagAwIBAgIUajK+4wn5EVISD6faBon6qq04IXAwDQYJKoZIhvcNAQEL
BQAwaTEXMBUGA1UEAwwOc3NscHJveHkubG9jYWwxCzAJBgNVBAYTAlVTMRMwEQYD
VQQIDApDYWxpZm9ybmlhMRQwEgYDVQQHDAtMb3MgQW5nZWxlczEWMBQGA1UECgwN
c3NscHJveHkgLkluYzAgFw0yMzEwMTIxMzQ1NDNaGA8yMTIzMDkxODEzNDU0M1ow
aTEXMBUGA1UEAwwOc3NscHJveHkubG9jYWwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
DApDYWxpZm9ybmlhMRQwEgYDVQQHDAtMb3MgQW5nZWxlczEWMBQGA1UECgwNc3Ns
cHJveHkgLkluYzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKNxJTKx
rqlAM7K714ofY/XRwgLZX9b73Q1iHjqFNOl9VLYdicsioW1MwnxzliJ4Y+gHnQhP
c056gxuDsV/ykdYQHltdIXGMB66Wl5PKS7uzoAUZ1A1xwbJmlwxuYDshd6oRpZJg
W/r+4Sqh8OmDYehq1ZwBfV3r3NWZEvCzon2lxfhaytViXm833LzfwoWVToOhWbMG
rsvlw41U42mM8xGj1tlAvAFGeWNv4Pr2SLsOdmS9z19blxcfAMNRZ/x0wCZJkSI3
cx8euoHNyjwnIA8JZF5CPn4fDRA4qB5M/iKbsYNcmyblDJXOebe9DHfqORgx1boI
ZXu6Yw3bp0elJasCAwEAAaOBuzCBuDAdBgNVHQ4EFgQUxmPOrxm7OCW4Ht4prQLb
WI7UJVEwHwYDVR0jBBgwFoAUxmPOrxm7OCW4Ht4prQLbWI7UJVEwDgYDVR0PAQH/
BAQDAgG+MDQGA1UdJQEB/wQqMCgGCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUH
AwMGCCsGAQUFBwMJMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0RBBgwFoIJbG9jYWxo
b3N0ggkxMjcuMC4wLjEwDQYJKoZIhvcNAQELBQADggEBAGc2xzseR1UU9FrC7iHB
G8CZxOTmkaYpJdYQRevNpPAAr84GR8pEQurJ/fHjXnYSMCfllcc9uUr/HxddEo2d
XhvmQYPZ+62OXRJZt2s3wm8C7L31AUcjL83aBmfBtmEvtPP4UV2ED4OWzd+w2Rgo
27LiIotzUsukEWCva80ABHL0bg2kSGP3Ymn5v21hLC235LwJvDYkmO36/1hisYku
IAJS0R1NnsG+vos/aRkq/P3c29P9+PzipiwE1DveTT5Tkknn9d0yl6KKnF6HdByp
45goJOTcm+3OCQbcouGDxyU5+B6wtLpElv/H4O9nZAx0PqISLnoTXFFBXIpIJfyr
izQ=
-----END CERTIFICATE-----
`
	block, _ := pem.Decode([]byte(caCertData))
	c, _ := x509.ParseCertificate(block.Bytes)
	return c
}
func loadCAKey() *rsa.PrivateKey {
	caKeyData := `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCjcSUysa6pQDOy
u9eKH2P10cIC2V/W+90NYh46hTTpfVS2HYnLIqFtTMJ8c5YieGPoB50IT3NOeoMb
g7Ff8pHWEB5bXSFxjAeulpeTyku7s6AFGdQNccGyZpcMbmA7IXeqEaWSYFv6/uEq
ofDpg2HoatWcAX1d69zVmRLws6J9pcX4WsrVYl5vN9y838KFlU6DoVmzBq7L5cON
VONpjPMRo9bZQLwBRnljb+D69ki7DnZkvc9fW5cXHwDDUWf8dMAmSZEiN3MfHrqB
zco8JyAPCWReQj5+Hw0QOKgeTP4im7GDXJsm5QyVznm3vQx36jkYMdW6CGV7umMN
26dHpSWrAgMBAAECggEBAJlyS8MpcFr0rNTcaIMD75xFf4mfPcygECxVdx3oHAIu
qc6FMu4lKDtuupWPC2B3eQzJwROhTBddDCRT4r67BVJdNbL/X7u0BS5TsiGN5sZl
4RGI6z5oE7uDd8KzCePaCvf/s1wW3aRrkUiuW3lQ4SYMz1m1SFdabq2XFmIntKGS
9liFEUAyM2J6wwMxljE3Jl3vlmmMUJL0h6o2uB93oXIgWpKhVMkn73TbPRSLiDeN
YvEpm/ExScQOKWo5iTefE84B+Uz1UXNonCmAStpGbf8g4KNd9vkCfjOKEkFKtax4
dPJ1DrLNvcQbqdFkwxVV/X5Rji/uR3gaZrlf8GyqMQkCgYEA05l3j4ixgB+92Pz4
dF7f2k0E3cyilF/DBquzBpJgLbx5sGhyrFnTM7aw4DZm/1LxFnL8uXD9piZLSFw6
Q5K84QzYodR3S/8bt4ua4HhgdIS5JTUqDH0Q4YejzsWAVRkU1uzn48GLnDpF61Ha
E8eNb5pNaK7DgfZqXVjVPk0We60CgYEAxbzKoohC1F0bNEAZQq5flIDyCJqaGXfv
UWvjhCKJnroj2inodFsv2cHJqJ4DU/Y+bMLQ1mDQDiJvRJ5qJSlF2w8diJHJdm+x
IciEb2xFwGQei3DQKBbkgjl3OvMmqMQaD0lnr0MuLJgF7uqRJoWpV/NmqhMNPRB/
vtxWDttVUbcCgYEAz8h8ynq9aoZA4+oNhCCCCxjkdXT0FWUv2sYSJ5rnTSIuENeP
+8S9C6QTbiid3Y0x5wyFNQhKW7Rw6p5+LErUpN37gHZlqz/YlNVHAbPTa7fFI09g
eiD5ya1rYqk4itf1SdQbJeCx2niynhCjaBblwTixWOF8ZIt4CTApPmNud4UCgYB9
dSwn9UZZkP1KqISebx5LjYiC9vxgvlzEDyzaUEN6xuUqbT6EXLq+cZqt9htscSbo
QK7Z5bD71tM7+Tqle0tMEooNdVoaYAFFywBj5ZFX4O4UUK5xUR0IlsdUSqOznkBe
hJdZdslcF9Rj4sXXaCSqnc78h3v1y3sRsKCVaon2fwKBgQC8GION7YBsAO9HbOoe
X0OQ/+GtjO7p5rZjtkOZ4yOTe3i/HkK+MEt7fXwCiDeX3kBVEWI/TAeRofo1HNIN
8C7qWsWoDuxN79KFaEdrUCRjFToU0bErcsKAwzZ//Gw+GZbRoklHBJ3iuUpvRH7b
RkysEHu/kTb0T2UILBoF/QR3FQ==
-----END PRIVATE KEY-----
`
	block, _ := pem.Decode([]byte(caKeyData))
	k, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	return k.(*rsa.PrivateKey)
}
