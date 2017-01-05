package ttls

import (
	"crypto/tls"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"crypto/x509/pkix"
	"time"
	"crypto/rand"
	"net"
)

type TTLS struct {
	Listener net.Listener
	x509Opts *x509Opts
}

type x509Opts struct {
	SubjectKeyId *[]byte
	SerialNumber *big.Int
	Country      *string
	Organization *string
}

func NewTTLSListener(laddr string, x509Opts *x509Opts) (*TTLS, error) {
	t := TTLS{
		x509Opts:x509Opts,
	}
	listener, err := tls.Listen("tcp", laddr, *t.getConfig())
	if err != nil {
		return &t, err
	}
	t.Listener = listener
	return &t, nil
}

func (t *TTLS)getConfig() *tls.Config {
	config := &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion: tls.VersionTLS12,
		Rand:rand.Reader,
	}
	config.Certificates = t.getCertificates()
	return config
}

func (t *TTLS)getCertificates() ([]tls.Certificate, error) {
	x509Cert, privateKey, err := t.getX509Certificate()
	if err != nil {
		return []tls.Certificate{}, err
	}
	return []tls.Certificate{
		Certificate:[][]byte{x509Cert},
		PrivateKey:privateKey,
	}, nil
}

func (t *TTLS)getPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func (t *TTLS)getX509Template() *x509.Certificate {

	crt := &x509.Certificate{
		IsCA : true,
		BasicConstraintsValid : true,
		SubjectKeyId : []byte{1, 2, 3},
		SerialNumber : big.NewInt(1234),
		Subject : pkix.Name{
			Country : []string{"US"},
			Organization: []string{"World Wide Web"},
		},
		NotBefore : time.Now(),
		NotAfter : time.Now().AddDate(5, 5, 5),
		// http://golang.org/pkg/crypto/x509/#KeyUsage
		ExtKeyUsage : []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage : x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	if t.x509Opts.SubjectKeyId != nil {
		crt.SubjectKeyId = *t.x509Opts.SubjectKeyId
	}

	if t.x509Opts.SerialNumber != nil {
		crt.SerialNumber = *t.x509Opts.SerialNumber
	}

	if t.x509Opts.Country != nil {
		crt.Subject.Country = *t.x509Opts.Country
	}

	if t.x509Opts.Organization != nil {
		crt.Subject.Organization = *t.x509Opts.Organization
	}

	return crt

}

func (t *TTLS)getX509Certificate() ([]byte, rsa.PrivateKey, error) {
	privateKey, err := t.getPrivateKey()
	if err != nil {
		return []byte{}, rsa.PrivateKey{}, err
	}
	template := t.getX509Template()
	x509crt, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return []byte{}, privateKey, err
	}
	return x509crt, privateKey, err
}