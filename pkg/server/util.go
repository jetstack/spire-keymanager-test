package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func makeFingerprint(pkixData []byte) string {
	s := sha256.Sum256(pkixData)
	return hex.EncodeToString(s[:])
}

func (m *Plugin) generateKeyEntry(keyID string, keyType keymanagerv1.KeyType) (e *KeyEntry, err error) {
	var privateKey crypto.Signer
	switch keyType {
	case keymanagerv1.KeyType_EC_P256:
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case keymanagerv1.KeyType_EC_P384:
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case keymanagerv1.KeyType_RSA_2048:
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case keymanagerv1.KeyType_RSA_4096:
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unable to generate key %q for unknown key type %q", keyID, keyType)
	}
	if err != nil {
		return nil, err
	}

	entry, err := makeKeyEntry(keyID, keyType, privateKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to make key entry for new key %q: %v", keyID, err)
	}

	return entry, nil
}

func makeKeyEntry(keyID string, keyType keymanagerv1.KeyType, privateKey crypto.Signer) (*KeyEntry, error) {
	pkixData, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for entry %q: %w", keyID, err)
	}

	return &KeyEntry{
		PrivateKey: privateKey,
		PublicKey: &keymanagerv1.PublicKey{
			Id:          keyID,
			Type:        keyType,
			PkixData:    pkixData,
			Fingerprint: makeFingerprint(pkixData),
		},
	}, nil
}

func clonePublicKey(publicKey *keymanagerv1.PublicKey) *keymanagerv1.PublicKey {
	return proto.Clone(publicKey).(*keymanagerv1.PublicKey)
}

func prefixStatus(err error, prefix string) error {
	st := status.Convert(err)
	if st.Code() != codes.OK {
		return status.Error(st.Code(), prefix+": "+st.Message())
	}
	return err
}

func entriesSliceFromMap(entriesMap map[string]*KeyEntry) (entriesSlice []*KeyEntry) {
	for _, entry := range entriesMap {
		entriesSlice = append(entriesSlice, entry)
	}
	SortKeyEntries(entriesSlice)
	return entriesSlice
}

func SortKeyEntries(entries []*KeyEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Id < entries[j].Id
	})
}

func (p *Plugin) getPrivateKeyAndFingerprint(id string) (crypto.Signer, string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if entry := p.entries[id]; entry != nil {
		return entry.PrivateKey, entry.PublicKey.Fingerprint, true
	}
	return nil, "", false
}
