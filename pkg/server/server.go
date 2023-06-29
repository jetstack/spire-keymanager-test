package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	"github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GenerateKey implements the KeyManager GenerateKey RPC. Generates a new private key with the given ID.
// If a key already exists under that ID, it is overwritten and given a different fingerprint.
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	resp, err := p.generateKey(ctx, req)
	return resp, prefixStatus(err, "failed to generate key")
}

func (p *Plugin) generateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}

	newEntry, err := p.generateKeyEntry(req.KeyId, req.KeyType)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.entries[req.KeyId] = newEntry

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: clonePublicKey(newEntry.PublicKey),
	}, nil
}

// GetPublicKey implements the KeyManager GetPublicKey RPC. Gets the public key information for the private key managed
// by the plugin with the given ID. If a key with the given ID does not exist, NOT_FOUND is returned.
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	resp := new(keymanagerv1.GetPublicKeyResponse)
	entry := p.entries[req.KeyId]
	if entry != nil {
		resp.PublicKey = clonePublicKey(entry.PublicKey)
	}

	return resp, nil
}

// GetPublicKeys implements the KeyManager GetPublicKeys RPC. Gets all public key information for the private keys
// managed by the plugin.
func (p *Plugin) GetPublicKeys(ctx context.Context, req *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	resp := new(keymanagerv1.GetPublicKeysResponse)
	for _, entry := range entriesSliceFromMap(p.entries) {
		resp.PublicKeys = append(resp.PublicKeys, clonePublicKey(entry.PublicKey))
	}

	return resp, nil
}

// SignData implements the KeyManager SignData RPC. Signs data with the private key identified by the given ID. If a key
// with the given ID does not exist, NOT_FOUND is returned. The response contains the signed data and the fingerprint of
// the key used to sign the data. See the PublicKey message for more details on the role of the fingerprint.
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	p.logger.Info("HELLO WORLD")
	resp, err := p.signData(req)
	return resp, prefixStatus(err, "failed to sign data")
}

func (p *Plugin) signData(req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	var signerOpts crypto.SignerOpts
	switch opts := req.SignerOpts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		if opts.HashAlgorithm == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, status.Error(codes.InvalidArgument, "hash algorithm is required")
		}
		signerOpts = crypto.Hash(opts.HashAlgorithm)
	case *keymanagerv1.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return nil, status.Error(codes.InvalidArgument, "PSS options are nil")
		}
		if opts.PssOptions.HashAlgorithm == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, status.Error(codes.InvalidArgument, "hash algorithm in PSS options is required")
		}
		signerOpts = &rsa.PSSOptions{
			SaltLength: int(opts.PssOptions.SaltLength),
			Hash:       crypto.Hash(opts.PssOptions.HashAlgorithm),
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported signer opts type %T", opts)
	}

	privateKey, fingerprint, ok := p.getPrivateKeyAndFingerprint(req.KeyId)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no such key %q", req.KeyId)
	}

	signature, err := privateKey.Sign(rand.Reader, req.Data, signerOpts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "keypair %q signing operation failed: %v", req.KeyId, err)
	}

	return &keymanagerv1.SignDataResponse{
		Signature:      signature,
		KeyFingerprint: fingerprint,
	}, nil
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
// TODO: Remove if the plugin does not need the logger.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}
