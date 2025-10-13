package engine

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/docker/secrets-engine/x/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLS(t *testing.T) {
	tlsCfg, err := newTLS()
	require.NoError(t, err)

	cr, err := cert.GenerateCertificateRequest()
	require.NoError(t, err)

	ca, err := cert.NewRootCA()
	signedCert, err := ca.SignCertificate(cr.PEM)
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	server.TLS = tlsCfg
	server.StartTLS()

	b, _ := pem.Decode(signedCert)
	assert.NotNil(t, b)
	assert.Equal(t, b.Type, "CERTIFICATE")

	pair, err := tls.X509KeyPair(signedCert, cr.PrivateKeyPEM)
	assert.NoError(t, err)

	pool := x509.NewCertPool()
	assert.True(t, pool.AppendCertsFromPEM(ca.GetPublicKeyPEM()))

	client := server.Client()

	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			Certificates: []tls.Certificate{pair},
			ServerName:   "docker-secrets-engine.local",
			GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				fmt.Printf("server requested certificate: %s\n", cri.AcceptableCAs)
				return &pair, nil
			},
		},
	}

	client.Transport = transport

	req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL, nil)
	assert.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "OK", string(data))
}
