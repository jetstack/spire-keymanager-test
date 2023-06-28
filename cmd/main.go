package main

import (
	"github.com/jetstack/spire-keymanager-test/pkg/server"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
)

func main() {
	plugin := new(server.Plugin)
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		keymanagerv1.KeyManagerPluginServer(plugin),
	)
}
