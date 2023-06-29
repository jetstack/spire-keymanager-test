FROM ghcr.io/spiffe/spire-server:1.6.0 
COPY ./bin/test-keymanager /opt/spire/bin/test-keymanager
ENTRYPOINT ["/opt/spire/bin/spire-server", "run"]

