package secretfile

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/docker/secrets-engine/store"
)

type EncryptedSecret struct {
	KeyType       KeyType
	EncryptedData []byte
}

func IDToDirName(id store.ID) string {
	return base64.StdEncoding.EncodeToString([]byte(id.String()))
}

func DirNameToID(dirName string) (store.ID, error) {
	s, err := base64.StdEncoding.DecodeString(dirName)
	if err != nil {
		return nil, err
	}
	return store.ParseID(string(s))
}

const (
	SecretFileName   = "secret"
	MetadataFileName = "metadata.json"
)

// atomicWrite writes the file to a temporary file first and upon successful write
// renames the file.
// This function does not guarantee concurrent writes and does not clean temporary
// files upon failure.
func atomicWrite(fs *os.Root, fileName string, data []byte) error {
	tmpFileName := fileName + ".tmp"
	tmpFile, err := fs.Create(tmpFileName)
	if err != nil {
		return err
	}
	defer func() {
		_ = tmpFile.Close()
	}()

	if _, err = tmpFile.Write(data); err != nil {
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		return err
	}

	if err := fs.Rename(tmpFileName, fileName); err != nil {
		return err
	}

	return nil
}

// Persist writes a secret and its metadata to a new directory on disk.
//
// The directory name is derived from the secret ID, base64-encoded to
// avoid unsupported characters. If the directory already exists, it is
// removed before writing, ensuring that secrets encrypted with different
// keys cannot become inconsistent.
//
// Inside the directory, the function creates:
//   - metadata.json — a JSON-encoded metadata file (always public)
//   - secret<KeyType> — one encrypted secret file per key type
//
// If any step fails, the directory is removed to prevent partial or
// inconsistent state. An error is returned in such cases.
func Persist(id store.ID, root *os.Root, metadata map[string]string, secrets []EncryptedSecret) error {
	secretDirName := IDToDirName(id)

	// always remove the directory before writing
	// this prevents secrets encrypted with different keys from becoming
	// out of sync.
	if _, err := root.Stat(secretDirName); err == nil {
		if err := root.RemoveAll(secretDirName); err != nil {
			return err
		}
	}

	if err := root.Mkdir(secretDirName, 0o700); err != nil {
		return err
	}

	var err error
	// remove the secre directory if any error occurs
	defer func() {
		if err != nil {
			_ = root.RemoveAll(secretDirName)
		}
	}()

	secretDir, err := root.OpenRoot(secretDirName)
	if err != nil {
		return err
	}
	defer func() {
		_ = secretDir.Close()
	}()

	meta, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	if err := atomicWrite(secretDir, MetadataFileName, meta); err != nil {
		return err
	}

	for _, s := range secrets {
		if err := atomicWrite(secretDir, SecretFileName+string(s.KeyType), s.EncryptedData); err != nil {
			return err
		}
	}

	return nil
}

// RestoreSecret reads the secret and metadata files from its scoped directory
func RestoreSecret(id store.ID, root *os.Root) ([]EncryptedSecret, map[string]string, error) {
	secretDir, err := root.OpenRoot(IDToDirName(id))
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = secretDir.Close()
	}()

	metadata, err := RestoreMetadata(id, secretDir)
	if err != nil {
		return nil, nil, err
	}

	files, err := fs.ReadDir(secretDir.FS(), ".")
	if err != nil {
		return nil, nil, err
	}

	var secrets []EncryptedSecret
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if !strings.HasPrefix(file.Name(), SecretFileName) {
			continue
		}
		encryptedData, err := secretDir.ReadFile(file.Name())
		if err != nil {
			continue
		}
		secrets = append(secrets, EncryptedSecret{
			KeyType:       KeyType(strings.ReplaceAll(file.Name(), SecretFileName, "")),
			EncryptedData: encryptedData,
		})
	}

	return secrets, metadata, nil
}

// RestoreMetadata reads and unmarshals the [metadataFileName] file
func RestoreMetadata(id store.ID, secretDir *os.Root) (map[string]string, error) {
	metadataStore, err := secretDir.Open(MetadataFileName)
	if err != nil {
		return nil, err
	}
	defer metadataStore.Close()

	b, err := io.ReadAll(metadataStore)
	if err != nil {
		return nil, err
	}

	var metadata map[string]string
	if err := json.Unmarshal(b, &metadata); err != nil {
		return nil, err
	}

	return metadata, nil
}
