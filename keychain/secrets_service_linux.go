package keychain

import (
	"context"
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
)

type SecretsService struct {
	conn *dbus.Conn
}

type SecretsAPI interface {
	PropertiesForCollection(label string) map[string]dbus.Variant
	SecretObject() dbus.BusObject
	CreateCollection(ctx context.Context, label, alias string) error
	GetCollections(ctx context.Context) ([]dbus.ObjectPath, error)
}

type serviceSecret struct {
	algorithm  string
	parameters []byte
	value      []byte
}

const (
	DefaultCollection       = "org.freedesktop.secrets"
	SecretServiceObjectPath = "/org/freedesktop/secrets"
	SecretsServiceName      = "org.freedesktop.secrets"
	// SecretServiceInterface
	//
	// Methods:
	// 	OpenSession() (result dbus.ObjectPath)
	// 	CreateCollection(label string, private bool)
	// 	LockService()
	// 	SearchCollections(fields map[string]string) (results []dbus.ObjectPath, locked []dbus.ObjectPath)
	//	RetrieveSecrets(items []dbus.ObjectPath) (secrets []serviceSecret)
	//
	// Signals:
	//	CollectionCreated() (collection dbus.ObjectPath)
	//	CollectionDeleted()	(collection dbus.ObjectPath)
	//
	// Properties:
	//	Collections []dbus.ObjectPath
	//	DefaultCollection dbus.ObjectPath
	SecretServiceInterface = "org.freedesktop.Secret.Service"
)

var ErrCreateCollection = errors.New("could not create a collection")

func NewSecretService() (SecretsAPI, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, err
	}
	return &SecretsService{
		conn: conn,
	}, nil
}

func (s *SecretsService) SecretObject() dbus.BusObject {
	return s.conn.Object(SecretsServiceName, SecretServiceObjectPath)
}

func (s *SecretsService) PropertiesForCollection(label string) map[string]dbus.Variant {
	return map[string]dbus.Variant{
		"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant(label),
	}
}

func (s *SecretsService) CreateCollection(ctx context.Context, label, alias string) error {
	properties := s.PropertiesForCollection(label)
	err := s.SecretObject().CallWithContext(ctx, SecretServiceInterface+".CreateCollection", 0, properties, alias).Err
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCreateCollection, err)
	}
	return nil
}

func (s *SecretsService) GetCollections(ctx context.Context) ([]dbus.ObjectPath, error) {
	var collections []dbus.ObjectPath
	variant, err := s.SecretObject().GetProperty(SecretServiceInterface + ".Collections")
	if err != nil {
		return nil, err
	}
	collections, ok := variant.Value().([]dbus.ObjectPath)
	if !ok {
		return nil, fmt.Errorf("variant %T, not of expected type", variant.Value())
	}
	return collections, nil
}
