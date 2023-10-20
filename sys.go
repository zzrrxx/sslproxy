package sslproxy

import (
	"crypto/x509"
	"syscall"
	"unsafe"
)

//go:build: windows

const (
	certStoreProvSystemW        = 10
	certStoreOpenExistingFlag   = 0x4000
	certSystemStoreCurrentUser  = 1 << 16
	certSystemStoreLocalMachine = 2 << 16
	certStoreAddReplaceExisting = 3
	x509AsnEncoding             = 1
)

var (
	crypt32                                 = syscall.NewLazyDLL("crypt32.dll")
	syscallCertAddEncodedCertificateToStore = crypt32.NewProc("CertAddEncodedCertificateToStore")
	syscallCertDeleteCertificateFromStore   = crypt32.NewProc("CertDeleteCertificateFromStore")
)

func ImportCAToSystemRoot(cert *x509.Certificate) error {

	dwFlag := certStoreOpenExistingFlag | certSystemStoreCurrentUser | certStoreAddReplaceExisting
	utf16Ptr, err := syscall.UTF16PtrFromString("root")
	if err != nil {
		return err
	}
	store, err := syscall.CertOpenStore(certStoreProvSystemW, 0, 0, uint32(dwFlag), uintptr(unsafe.Pointer(utf16Ptr)))
	if err != nil {
		return err
	}
	defer syscall.CertCloseStore(store, 0)

	data := cert.Raw
	_, _, err = syscallCertAddEncodedCertificateToStore.Call(uintptr(store), x509AsnEncoding, uintptr(unsafe.Pointer(&data[0])), uintptr(uint(len(data))), 4, 0)
	if err.(syscall.Errno) != 0 {
		return err
	}

	return nil
}

func RemoveCAFromSystemRoot(name string) error {
	dwFlag := certStoreOpenExistingFlag | certSystemStoreCurrentUser | certStoreAddReplaceExisting
	utf16Ptr, err := syscall.UTF16PtrFromString("root")
	if err != nil {
		return err
	}
	store, err := syscall.CertOpenStore(certStoreProvSystemW, 0, 0, uint32(dwFlag), uintptr(unsafe.Pointer(utf16Ptr)))
	if err != nil {
		return nil
	}
	defer syscall.CertCloseStore(store, 0)

	certs := make([]*syscall.CertContext, 0)
	var cert *syscall.CertContext
	for {
		cert, err = syscall.CertEnumCertificatesInStore(store, cert)
		if err != nil {
			break
		}

		buf := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:]
		buf2 := make([]byte, cert.Length)
		copy(buf2, buf)

		c, err := x509.ParseCertificate(buf2)
		if err != nil {
			return err
		}

		if c.Subject.CommonName == name ||
			(len(c.Subject.Names) > 0 && c.Subject.Names[0].Value == name) ||
			(len(c.Subject.Organization) > 0 && c.Subject.Organization[0] == name) {
			certs = append(certs, cert)
		}
	}

	for _, cert := range certs {
		_, _, err = syscallCertDeleteCertificateFromStore.Call(uintptr(unsafe.Pointer(cert)))
	}

	if se, ok := err.(syscall.Errno); ok && se != 0 {
		return err
	}

	return nil
}
