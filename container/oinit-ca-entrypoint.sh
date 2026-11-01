#!/bin/sh
# Entrypoint for the oinit-ca image.
#
# Generates the default CA key pair on first start (what the oinit-ca
# deb postinstall script does), checks that a config file is supplied
# via -c, and then drops privileges to the oinit user to run the server.
set -eu

OINIT_DIR=/etc/oinit
install -d -m 0750 "$OINIT_DIR"

# Generate the default CA key pairs on first start, BEFORE the config check:
# the keys do not depend on the config file, and provisioning flows (such as
# the compose demo) need the key material while the config is still being
# installed. This mirrors the oinit-ca deb postinstall script.
for key in host-ca user-ca; do
    if [ ! -e "$OINIT_DIR/$key" ]; then
        ssh-keygen -q -t ed25519 -N '' -f "$OINIT_DIR/$key" -C "oinit CA ($key)" >/dev/null
        echo "Generated CA key pair: $OINIT_DIR/$key"
    fi
done

# Whether the caller supplied "-c <config>": check the following argument
# of any -c occurrence in the composed command line.
config_found=0
config_path=""
prev=""
for arg in "$@"; do
    if [ "$prev" = "-c" ] || [ "$prev" = "--config" ]; then
        config_found=1
        config_path="$arg"
    fi
    prev="$arg"
done
if [ "$config_found" != "1" ]; then
    echo "ERROR: no config file given." >&2
    echo "Usage: oinit-ca -c <path/to/config> [-l <host:port>]" >&2
    echo "Mount your config (start from /usr/share/oinit-ca/config.sample.ini)" >&2
    exit 1
fi
if [ ! -r "$config_path" ]; then
    echo "ERROR: config file is not readable: $config_path" >&2
    echo "Start from /usr/share/oinit-ca/config.sample.ini:" >&2
    echo "  docker run ... -v ./ca-config.ini:/etc/oinit/ca-config.ini:ro ..." >&2
    exit 1
fi

chown -R oinit:oinit "$OINIT_DIR" 2>/dev/null || true
chown oinit:oinit /var/oinit 2>/dev/null || true

exec su-exec oinit:oinit /usr/bin/oinit-ca "$@"
