package main

import (
	keymanagerbase "github.com/jetstack/spire-keymanager-test/pkg/base"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
)

type KeyManager struct {
	*keymanagerbase.Base
}

func main() {
	keymanager := &KeyManager{
		Base: keymanagerbase.New(keymanagerbase.Config{}),
	}
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		keymanagerv1.KeyManagerPluginServer(keymanager),
	)
}
