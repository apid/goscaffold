package goscaffold

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func decodePEM(fileName string, pwFunc func() []byte) ([]byte, string, error) {
	pb, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode(pb)
	if x509.IsEncryptedPEMBlock(block) {
		if pwFunc == nil {
			return nil, "", errors.New("Cannot read encrypted file without password")
		}
		dec, err := x509.DecryptPEMBlock(block, pwFunc())
		if err != nil {
			return nil, "", err
		}
		return dec, block.Type, nil
	}
	return block.Bytes, block.Type, nil
}

func getCertificate(certFile, keyFile string, pwFunc func() []byte) (tls.Certificate, error) {
	ret := tls.Certificate{}

	certBytes, _, err := decodePEM(certFile, nil)
	if err != nil {
		return ret, err
	}
	ret.Certificate = [][]byte{certBytes}

	keyBytes, keyType, err := decodePEM(keyFile, pwFunc)
	if err != nil {
		return ret, err
	}
	switch keyType {
	case "RSA PRIVATE KEY":
		pk, err := x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			return ret, err
		}
		ret.PrivateKey = pk
	default:
		return ret, fmt.Errorf("Invalid private key type %s", keyType)
	}

	return ret, nil
}
