package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"time"
)

type rootCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func (r *rootCA) GetPublicKeyPEM() []byte {
	return r.pem
}

func (r *rootCA) SignCertificate(certificateRequestPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(certificateRequestPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("expected PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},

		DNSNames:       csr.DNSNames,
		EmailAddresses: csr.EmailAddresses,
		IPAddresses:    csr.IPAddresses,
		URIs:           csr.URIs,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, r.cert, csr.PublicKey, r.key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

type RootCA interface {
	SignCertificate(certificateRequestPEM []byte) ([]byte, error)
	GetPublicKeyPEM() []byte
	GenerateServerCert() (*tls.Certificate, error)
}

// NewRootCA generates a new root CA once.
// Calling this function again will return the originally generated root CA.
var NewRootCA = sync.OnceValues[RootCA, error](func() (RootCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ski := sha1.Sum(pubDER) // SKI traditionally uses SHA-1 over SPKI

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Secrets Engine",
			Organization: []string{"Docker Inc."},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           nil,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski[:],
		AuthorityKeyId:        ski[:],
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &rootCA{
		cert: cert,
		key:  key,
		pem:  certPEM,
	}, nil
})

func (r *rootCA) GenerateServerCert() (*tls.Certificate, error) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := &sk.PublicKey

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Secrets Engine",
			Organization: []string{"Docker Inc."},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames: []string{"docker-secrets-engine.local"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, r.cert, pub, r.key)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	derKey, _ := x509.MarshalECPrivateKey(sk)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derKey})

	serverCA, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	serverCA.Leaf = leaf

	return &serverCA, nil
}

type CertificateRequest struct {
	PrivateKeyPEM []byte
	PEM           []byte
}

func GenerateCertificateRequest() (*CertificateRequest, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privDer, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDer})

	tpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "secrets-engine-client",
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, privKey)
	if err != nil {
		return nil, err
	}

	cr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	return &CertificateRequest{
		PrivateKeyPEM: privKeyPEM,
		PEM:           cr,
	}, nil
}
