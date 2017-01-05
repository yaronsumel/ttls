package ttls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	mrand "math/rand"
	"net"
	"time"
)

// TTLS struct
type TTLS struct {
	Listener net.Listener
	x509Opts *X509Opts
}

// X509Opts .. for custom values
type X509Opts struct {
	SubjectKeyID string
	SerialNumber int64
	Country      string
	Organization string
}

// NewTTLSListener creates the resources needed to create tls server
func NewTTLSListener(laddr string, x509Opts *X509Opts) (*TTLS, error) {
	t := TTLS{
		x509Opts: x509Opts,
	}
	config, err := t.getConfig()
	if err != nil {
		return &t, err
	}
	listener, err := tls.Listen("tcp", laddr, config)
	if err != nil {
		return &t, err
	}
	t.Listener = listener
	return &t, nil
}

func (t *TTLS) getConfig() (*tls.Config, error) {
	var err error
	config := &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		Rand:                     rand.Reader,
	}
	config.Certificates, err = t.getCertificates()
	if err != nil {
		return &tls.Config{}, err
	}
	return config, nil
}

func (t *TTLS) getCertificates() ([]tls.Certificate, error) {
	x509Cert, privateKey, err := t.getX509Certificate()
	if err != nil {
		return []tls.Certificate{}, err
	}
	return []tls.Certificate{
		{
			Certificate: [][]byte{x509Cert},
			PrivateKey:  privateKey,
		},
	}, nil
}

func (t *TTLS) getPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func getRandInt64() int64 {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return int64(r.Int())
}

func (t *TTLS) getX509Template() (*x509.Certificate, error) {

	crt := &x509.Certificate{
		IsCA: true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte("TTLS"),
		SerialNumber:          big.NewInt(getRandInt64()),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"World Wide Web"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(5, 5, 5),
		// http://golang.org/pkg/crypto/x509/#KeyUsage
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	if t.x509Opts == nil {
		return crt, nil
	}

	if t.x509Opts.SubjectKeyID != "" {
		crt.SubjectKeyId = []byte(t.x509Opts.SubjectKeyID)
	}

	if t.x509Opts.SerialNumber != 0 {
		crt.SerialNumber = big.NewInt(t.x509Opts.SerialNumber)
	}

	if t.x509Opts.Country != "" {
		crt.Subject.Country = []string{t.x509Opts.Country}
	}

	if t.x509Opts.Organization != "" {
		crt.Subject.Organization = []string{t.x509Opts.Organization}
	}

	return crt, nil

}

func (t *TTLS) getX509Certificate() ([]byte, *rsa.PrivateKey, error) {
	privateKey, err := t.getPrivateKey()
	if err != nil {
		return []byte{}, &rsa.PrivateKey{}, err
	}
	template, err := t.getX509Template()
	if err != nil {
		return []byte{}, &rsa.PrivateKey{}, err
	}
	x509crt, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return []byte{}, privateKey, err
	}
	return x509crt, privateKey, err
}
