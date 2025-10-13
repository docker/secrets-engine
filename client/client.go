package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/docker/secrets-engine/x/api"
	v1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/cert"
	"github.com/docker/secrets-engine/x/secrets"
)

type (
	Envelope = secrets.Envelope
	ID       = secrets.ID
	Pattern  = secrets.Pattern
)

var (
	ParseID     = secrets.ParseID
	MustParseID = secrets.MustParseID

	ParsePattern     = secrets.ParsePattern
	MustParsePattern = secrets.MustParsePattern

	ErrSecretNotFound = secrets.ErrNotFound
)

var _ secrets.Resolver = &client{}

type Option func(c *config) error

func WithSocketPath(path string) Option {
	return func(s *config) error {
		if path == "" {
			return errors.New("no path provided")
		}
		if s.dialContext != nil {
			return errors.New("cannot set socket path and dial")
		}
		s.dialContext = dialFromPath(path)
		return nil
	}
}

func WithDialContext(dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(s *config) error {
		if s.dialContext != nil {
			return errors.New("cannot set socket path and dial")
		}
		s.dialContext = dialContext
		return nil
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(s *config) error {
		s.requestTimeout = timeout
		return nil
	}
}

type dial func(ctx context.Context, network, addr string) (net.Conn, error)

type config struct {
	dialContext    dial
	requestTimeout time.Duration
}

type client struct {
	resolverClient resolverv1connect.ResolverServiceClient
}

func New(options ...Option) (secrets.Resolver, error) {
	cfg := &config{
		requestTimeout: api.DefaultPluginRequestTimeout,
	}
	for _, opt := range options {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.dialContext == nil {
		cfg.dialContext = dialFromPath(api.DefaultSocketPath())
	}

	transport := &http.Transport{
		DialContext:        cfg.dialContext,
		DisableKeepAlives:  true,
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	c := &http.Client{
		Transport: transport,
		Timeout:   cfg.requestTimeout,
	}
	certResolver := resolverv1connect.NewCertServiceClient(c, "https://unix", connect.WithHTTPGet())

	// get the server's root CA (which is also generated upon server startup)
	rootCAResp, err := certResolver.GetCA(context.Background(),
		connect.NewRequest(&emptypb.Empty{}),
	)
	if err != nil {
		return nil, err
	}

	// generate a new private key for mTLS
	cr, err := cert.GenerateCertificateRequest()
	if err != nil {
		return nil, fmt.Errorf("could not create client certificate request: %w", err)
	}

	certificateRequestPEM := string(cr.PEM)

	// sign our client public key with the server's private key
	signedResp, err := certResolver.SignCert(context.Background(),
		connect.NewRequest(v1.SignCertRequest_builder{
			CertificateRequest: &certificateRequestPEM,
		}.Build()),
	)
	if err != nil {
		return nil, err
	}

	b, _ := pem.Decode([]byte(signedResp.Msg.GetSignedCertificate()))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE PEM, got %v", b.Type)
	}

	pair, err := tls.X509KeyPair([]byte(signedResp.Msg.GetSignedCertificate()), cr.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(rootCAResp.Msg.GetCaCertificate())) {
		return nil, errors.New("could not add server root CA")
	}

	if _, err := pair.Leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("issued cert doesn't verify against CA: %w", err)
	}

	c.CloseIdleConnections()

	// add our TLS config to future requests
	transport.TLSClientConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{pair},
		ServerName:   "docker-secrets-engine.local",
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			fmt.Printf("server requested certificate: %s\n", cri.AcceptableCAs)
			return &pair, nil
		},
	}

	c = &http.Client{
		Transport: transport,
		Timeout:   cfg.requestTimeout,
	}

	return &client{
		resolverClient: resolverv1connect.NewResolverServiceClient(c, "https://unix"),
	}, nil
}

func (c client) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	req := connect.NewRequest(v1.GetSecretsRequest_builder{
		Pattern: proto.String(pattern.String()),
	}.Build())
	resp, err := c.resolverClient.GetSecrets(ctx, req)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			err = secrets.ErrNotFound
		}
		return nil, err
	}

	var envelopes []secrets.Envelope
	for _, item := range resp.Msg.GetEnvelopes() {
		id, err := secrets.ParseID(item.GetId())
		if err != nil {
			continue
		}
		envelopes = append(envelopes, secrets.Envelope{
			ID:         id,
			Value:      item.GetValue(),
			Provider:   item.GetProvider(),
			Version:    item.GetVersion(),
			CreatedAt:  item.GetCreatedAt().AsTime(),
			ResolvedAt: item.GetResolvedAt().AsTime(),
			ExpiresAt:  item.GetExpiresAt().AsTime(),
		})
	}
	return envelopes, nil
}

func dialFromPath(path string) dial {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := &net.Dialer{}
		return d.DialContext(ctx, "unix", path)
	}
}
