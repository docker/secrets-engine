package resolver

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"

	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/cert"
	"github.com/docker/secrets-engine/x/logging"
)

var _ resolverv1connect.CertServiceHandler = &certificateService{}

type certificateService struct {
	rootCA cert.RootCA
	logger logging.Logger
}

func NewCertificateService(logger logging.Logger) (resolverv1connect.CertServiceHandler, error) {
	rootCA, err := cert.NewRootCA()
	if err != nil {
		return nil, err
	}
	return &certificateService{
		logger: logger,
		rootCA: rootCA,
	}, nil
}

func (c *certificateService) GetCA(context.Context, *connect.Request[emptypb.Empty]) (*connect.Response[resolverv1.GetCAResponse], error) {
	pem := string(c.rootCA.GetPublicKeyPEM())
	c.logger.Printf("public PEM: %s", pem)
	return connect.NewResponse(resolverv1.GetCAResponse_builder{
		CaCertificate: &pem,
	}.Build()), nil
}

func (c *certificateService) SignCert(ctx context.Context, req *connect.Request[resolverv1.SignCertRequest]) (*connect.Response[resolverv1.SignCertResponse], error) {
	t, err := c.rootCA.SignCertificate([]byte(req.Msg.GetCertificateRequest()))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	signed := string(t)

	c.logger.Printf("signed certificate: %s", signed)
	return connect.NewResponse(resolverv1.SignCertResponse_builder{
		SignedCertificate: &signed,
	}.Build()), nil
}
