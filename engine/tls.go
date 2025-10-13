package engine

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/docker/secrets-engine/x/cert"
	"github.com/docker/secrets-engine/x/logging"
)

var certPool = x509.NewCertPool()

func newTLS() (*tls.Config, error) {
	rootCA, err := cert.NewRootCA()
	if err != nil {
		return nil, err
	}

	if !certPool.AppendCertsFromPEM(rootCA.GetPublicKeyPEM()) {
		return nil, fmt.Errorf("could not append CA PEM")
	}

	serverPair, err := rootCA.GenerateServerCert()
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*serverPair},
		ClientCAs:    certPool,
		// we want to handle tls checks in a middleware
		ClientAuth: tls.VerifyClientCertIfGiven,
	}, nil
}

type checkCertMiddlewareConfig struct {
	logger logging.Logger
	// allowedRoutes are exact path matches that should be ignored
	allowedRoutes []string
}

func checkCertMiddleware(c *checkCertMiddlewareConfig) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, allowed := range c.allowedRoutes {
				if allowed == r.URL.Path || strings.HasPrefix(r.URL.Path, allowed) {
					next.ServeHTTP(w, r)
					return
				}
			}

			c.logger.Printf("checking route has valid certificate: %v", r.TLS)

			if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
				c.logger.Errorf("no client certificate provided for request: %s", r.URL.String())
				http.Error(w, "unauthorized", http.StatusForbidden)
				return
			}

			leaf := r.TLS.PeerCertificates[0]
			opts := x509.VerifyOptions{
				Roots:         certPool,
				CurrentTime:   time.Now(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				Intermediates: x509.NewCertPool(),
			}

			for _, ic := range r.TLS.PeerCertificates[1:] {
				opts.Intermediates.AddCert(ic)
			}

			for i, subj := range certPool.Subjects() {
				c.logger.Printf("pool[%d] subject DER=%x", i, subj) // or parse to Name
			}

			if _, err := leaf.Verify(opts); err != nil {
				var ua *x509.UnknownAuthorityError
				if errors.As(err, &ua) {
					c.logger.Printf("UnknownAuthority: cert.Issuer=%s (len Roots=%d, Intermediates=%d)",
						leaf.Issuer, len(certPool.Subjects()), len(r.TLS.PeerCertificates)-1)
				}
				c.logger.Errorf("invalid client certificate provided for request: %s with error: %s", r.URL.String(), err)
				http.Error(w, "unauthorized", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
