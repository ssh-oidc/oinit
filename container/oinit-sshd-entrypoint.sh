#!/bin/sh
# Entrypoint for the oinit-sshd image.
#
# - persists the SSH host key in /state/ssh
# - enables LDAP for NSS only when an /etc/nslcd.conf is mounted
#   (otherwise NSS stays "files only" and nslcd stays down)
# - exits until oinit CA assets are provisioned in /state/ssh/oinit
# - then supervises services via runsvdir
set -eu

install -d -m 0700 /state/ssh
install -d -m 0755 /state/ssh/oinit
install -d -m 0755 /run/sshd

if [ ! -f /state/ssh/host-key ]; then
    ssh-keygen -q -t ed25519 -N '' \
        -f /state/ssh/host-key \
        -C "oinit ssh host" >/dev/null
fi

if [ -e /etc/nslcd.conf ]; then
    cp /usr/share/oinit-sshd/nsswitch.ldap /etc/nsswitch.conf
    rm -f /etc/sv/nslcd/down
    install -d -m 0755 -o nslcd -g nslcd /run/nslcd
else
    touch /etc/sv/nslcd/down
fi

for file in /state/ssh/oinit/user-ca.pub /state/ssh/oinit/host-key-cert.pub; do
    if [ ! -s "$file" ]; then
        echo "ERROR: oinit is not provisioned: missing $file" >&2
        echo "Mount the user CA public key and the host certificate into /state/ssh/oinit." >&2
        echo "See container/README.md for the oinit bootstrap steps." >&2
        exit 1
    fi
done

exec runsvdir /etc/service
