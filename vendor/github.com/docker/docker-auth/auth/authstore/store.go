// authstore is a wrapper around the [github.com/docker/secrets-engine/store.Store]
// module.
//
// It sets up a [store.Secret] called [Credential] which stores Authentication
// specific secrets.
package authstore

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/keychain"
)

type Credential struct {
	Identifier  string `json:"identifier"`
	Secret      string `json:"secret"`
	RegistryURL string `json:"registry_url"`
	metadata    map[string]string
}

var _ store.Secret = &Credential{}

func (r *Credential) Metadata() map[string]string {
	return r.metadata
}

func (r *Credential) SetMetadata(metadata map[string]string) error {
	r.metadata = metadata
	return nil
}

func (r *Credential) Marshal() ([]byte, error) {
	src := fmt.Sprintf("%s:%s:%s", r.Identifier, r.Secret, r.RegistryURL)
	dest := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dest, []byte(src))
	return dest, nil
}

func (r *Credential) Unmarshal(data []byte) error {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	_, err := base64.StdEncoding.Decode(dst, data)
	if err != nil {
		return fmt.Errorf("failed to decode base64 data: %w", err)
	}
	parts := bytes.SplitN(dst, []byte{':'}, 3)
	if len(parts) != 3 {
		return fmt.Errorf("invalid format for registry credential, expected 'identifier:secret:registry_url', got %s", string(dst))
	}
	r.Identifier = string(parts[0])
	r.Secret = string(parts[1])
	r.RegistryURL = string(parts[2])
	return nil
}

// NewStore is a wrapper around [github.com/docker/secrets-engine/store.Store].
//
// It sets the serviceGroup and serviceName attributes along with the
// underlying secret type [Credential].
func NewStore(serviceGroup, serviceName string) (store.Store, error) {
	return keychain.New(
		serviceGroup,
		serviceName,
		func() *Credential { return &Credential{} },
	)
}
