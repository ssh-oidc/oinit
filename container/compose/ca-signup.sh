#!/bin/sh
# Helper for the compose demo (see container/README.md): run inside a
# container that mounts the CA keys at /ca (read-only) and the motley_cue
# appliance state at /state (read-write). Generates the SSH host key
# (idempotent), signs it as a host certificate with the CA, and stores the
# host certificate plus user CA public key where the appliance expects them.
set -eu

# A "docker compose run" does not execute the appliance entrypoint (which
# seeds the account database), but ssh-keygen needs /etc/passwd to resolve
# uid 0. Seed the persistent account database from the image templates.
mkdir -p /state/etc
for f in passwd group shadow gshadow subuid subgid; do
    template="/usr/share/motley-cue/state-templates/$f"
    if [ -e "$template" ] && [ ! -e "/state/etc/$f" ]; then
        cp -a "$template" "/state/etc/$f"
    fi
done

mkdir -p /state/ssh /state/ssh/oinit

if [ ! -f /state/ssh/host-key ]; then
    ssh-keygen -q -t ed25519 -N '' -f /state/ssh/host-key -C 'demo ssh host' >/dev/null
fi

# Copy the pub key to a writable location; ssh-keygen writes the certificate
# next to the source file, and /state may be read-only.
cp /state/ssh/host-key.pub /tmp/host-key.pub
ssh-keygen -q -s /ca/host-ca -I demo-host -h -n localhost /tmp/host-key.pub
cp /tmp/host-key-cert.pub /state/ssh/oinit/host-key-cert.pub

cp /ca/user-ca.pub /state/ssh/oinit/user-ca.pub

chmod 0644 /state/ssh/oinit/*
echo "Host key signed and CA assets installed in /state/ssh/oinit."
