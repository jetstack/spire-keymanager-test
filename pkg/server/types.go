package server

import (
	"crypto"
	"sync"

	hclog "github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
)

// Plugin implements the KeyManager plugin
type Plugin struct {
	// taken from keymanager base in spire codebase
	keymanagerv1.UnsafeKeyManagerServer
	logger  hclog.Logger
	mu      sync.RWMutex
	entries map[string]*KeyEntry
}

// KeyEntry is an entry maintained by the key manager
type KeyEntry struct {
	PrivateKey crypto.Signer
	*keymanagerv1.PublicKey
}

// Config defines the configuration for the plugin.
// TODO: Add relevant configurables or remove if no configuration is required.
type Config struct{}
