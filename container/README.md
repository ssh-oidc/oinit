# oinit container images

This directory contains a multi-target `Dockerfile` for the oinit project.
The build context is the repository root.

| Target | Purpose | Runs as |
| --- | --- | --- |
| `oinit-ca` | certificate-authority REST server | `oinit` (unprivileged) |
| `oinit-sshd` | OpenSSH host payload (`oinit-shell`/`oinit-switch`) | root |
| `oinit` | client CLI (`oinit add/list/match`) | `oinit` (unprivileged) |

A dedicated GitHub Actions workflow (`.github/workflows/publish-images.yml`)
publishes these images to the sshoidc Docker Hub namespace on version tags,
multi-arch (`linux/amd64`, `linux/arm64`), tagged `latest` and `<version>`.

## oinit-ca

The CA validates OIDC access tokens against motley_cue and then signs
short-lived SSH user certificates (principals `oinit` and the provisioned
username, `force-command: oinit-switch ...`). It is the piece that connects
OIDC identities to the SSH hosts listed in its config.

```bash
docker run -d --name oinit-ca \
  -p 8082:8082 \
  -v oinit-ca-state:/etc/oinit \
  -v ca-config.ini:/etc/oinit/ca-config.ini \
  sshoidc/oinit-ca:latest
```

- Configuration: `/etc/oinit/ca-config.ini`; the sample
  `configs/config.sample.ini` is shipped inside the image at
  `/usr/share/oinit-ca/config.sample.ini`. The listen address comes from
  `listen-address` (or `docker run sshoidc/oinit-ca ... -l 0.0.0.0:8082`).
- CA keys: `/etc/oinit` must be a persistent volume. On first start the
  entrypoint generates the default `host-ca`/`user-ca` ed25519 key pairs
  (what the deb postinstall script does) and chowns the volume to the `oinit`
  user.
- The "host configuration" comments in `internal/api` and the sample config
  need reading before use; root access and the user allow/block lists are
  additionally gated by `oinit-switch.conf` and PAM on the SSH hosts.

## oinit-sshd

`oinit-sshd` is the container equivalent of the `oinit-openssh` package: an
OpenSSH server.

The login flow (users always connect as `oinit`):

```
ssh -i ~/.ssh/... -cert ... oinit@host
   └─ sshd: certificate principals validated against
      /state/ssh/oinit/user-ca.pub
   └─ login shell /usr/bin/oinit-shell  (system user "oinit")
   └─ force-command: oinit-switch <provisioned-username>
   └─ oinit-switch: su to the provisioned account (via the PAM su rule)
```

### State

- `/state` volume:
  - `/state/ssh/host-key` — generated on first start, must persist
  - `/state/ssh/oinit/host-key-cert.pub` — host certificate signed by the CA
  - `/state/ssh/oinit/user-ca.pub` — user CA public key from the CA operator

The container refuses to start until the two files under `/state/ssh/oinit`
are present; take the host public key (`/state/ssh/host-key.pub`) to the CA
operator and request a host certificate.

### Account sources

The image does NOT provision accounts. Pick one:

- files (default): bind-mount host `/etc/passwd`, `/etc/group`, `/etc/shadow`,
  and an NSS `files`-only `/etc/nsswitch.conf` over the image files.
- LDAP: mount a real `/etc/nslcd.conf` (template:
  `container/nslcd.conf.template`). The entrypoint then switches NSS to
  `files ldap` and starts nslcd.

In federated deployments accounts typically come from motley_cue (its
`local_unix` or LDAP backend `user/deploy`), but any pre-existing account
reachable via NSS works.

## oinit

```bash
docker run --rm sshoidc/oinit:latest add -y localhost:8080 http://ca.example.org:8082
docker run --rm sshoidc/oinit:latest list
```

Mount `/var/oinit` to persist the client config (`~/.config/oinit`).

## Demo stack

`container/compose/demo.yaml` activates the full chain in one compose:

1. `docker compose up -d oinit-ca` — generates the CA key pairs.
2. `docker compose run --rm --entrypoint sh motley-cue /ca-signup.sh`
   — generates the appliance SSH host key, signs it with the CA, and
   installs `host-key-cert.pub` + `user-ca.pub` in `/state/ssh/oinit`.
3. `docker compose up -d motley-cue` — the appliance comes up with sshd
   (certificate login) and motley_cue (local_unix account provisioning).
4. Configure the CA hostgroup and restart:
   ```bash
   docker compose cp demo-ca-config.ini oinit-ca:/etc/oinit/ca-config.ini
   docker compose restart oinit-ca
   ```
5. Deploy a user via motley_cue, get a certificate via `oinit`, login:
   `ssh oinit@localhost -p 2222`.

## How the images work with motley_cue

```
      OIDC access token / oinit client
                 │
                 ▼
           ┌──────────┐  POST token  ┌──────────────┐
           │ oinit-ca  │─────────────▶│  motley_cue  │
           │           │  /user/deploy│  provisions   │
           │  signs    │              │  local_unix / │
           │  SSH cert │              │  LDAP account │
           └──────────┘              └──────────────┘
                 │      certificate (principal: oinit + provisioned user,
                 │      force-command oinit-switch)
                 ▼
        ┌─────────────────────┐
        │  SSH host            │
        │  oinit-shell         │  (allinone-oinit, sshd-oinit or oinit-sshd)
        │  oinit-switch su     │
        │  provisioned account │
        └─────────────────────┘
```

- The contents of allinone-oinit and sshd-oinit (motley_cue repo) and
  `oinit-sshd` (this repo) are identical at the oinit level: same binaries,
  same configs, same PAM rule. Which one to use depends on how accounts are
  provisioned and whether motley_cue must run in the same container.
- webssh-oidc also speaks the oinit protocol (optional `OINIT_ENDPOINT`
  pointing at `http://oinit-ca:8082/oinit/api/v1` with
  `SSH_METHOD=oinit`).
