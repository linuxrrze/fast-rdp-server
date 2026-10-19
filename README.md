# fastrdp – multi-user Linux RDP terminal server

A Windows-RDS-style terminal server for Linux, built from maintained parts:

- **One front-end:** `freerdp-proxy3` with Kerberos NLA, plus a small module that
  asks a session broker before letting anyone in.
- **MFA:** privacyIDEA (TOTP/HOTP, YubiKey OTP, push), shared with Keycloak.
- **All common desktops:**
  - X11 desktops (Xfce, MATE, Cinnamon, LXQt, Plasma X11) through **xrdp 0.10.6**
    with H.264.
  - **GNOME 50** through GDM headless sessions + gnome-remote-desktop.
  - **Plasma 6 Wayland** through KWin's virtual backend + KRdp.
- **GPU where possible:**
  - glamor rendering on Intel/AMD.
  - VA-API/NVENC H.264 in the Wayland back-ends.
  - VirtualGL on NVIDIA.

Plan: [docs/plan.md](docs/plan.md) · Design: [docs/architecture.md](docs/architecture.md) ·
Auth/MFA: [docs/auth-matrix.md](docs/auth-matrix.md) · Desktops/GPU:
[docs/desktop-matrix.md](docs/desktop-matrix.md) · Performance: [docs/performance.md](docs/performance.md) ·
Clients: [docs/client-guide.md](docs/client-guide.md)

## Layout

```
broker/
  brokerd/            fastrdp-brokerd (Python 3.11+, stdlib only) + unit/protocol tests
  proxy-module/       freerdp-proxy3 module (C, CMake)
  pam_fastrdp_token/  PAM module: xrdp accepts only one-time broker tokens (C) + functional test
  session/            systemd units, PAM stacks, session launchers (startwm.sh, session-plasma)
ansible/              roles: base identity gpu desktops xrdp gnome_rd plasma_krdp mfa_privacyidea broker freerdp_proxy
tests/
  proxy-e2e/          real freerdp-proxy + module end-to-end tests (TLS, and Kerberos NLA with a throwaway KDC)
  smoke/              checks for a deployed host
  perf/               rdpbench (headless benchmark client), perfload, proxy-overhead/compare scripts
  gpu/                session_report.py: which renderer/H.264 encoder a session really uses
```

## Deploy (lab)

Target: Ubuntu 26.04 or Debian 13, joined to Samba AD / FreeIPA (or keytab provided).

```sh
cd ansible
$EDITOR inventories/lab/hosts.yml inventories/lab/group_vars/all/main.yml
cp inventories/lab/group_vars/all/vault.yml.example inventories/lab/group_vars/all/vault.yml
ansible-vault encrypt inventories/lab/group_vars/all/vault.yml
ansible-playbook site.yml --ask-vault-pass
sudo /path/to/repo/tests/smoke/check-host.sh alice          # on the host
```

Then connect: `xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM /sec:nla /gfx:avc444`.

## Tests

```sh
make test          # broker unit + protocol tests, PAM module test, ansible-lint, shellcheck
make test-e2e      # needs freerdp-proxy + freerdp3-dev + libcjson-dev
make test-e2e-nla  # additionally krb5-kdc, krb5-admin-server, krb5-user
```

## Status (phases 1–3)

| Area | State |
|---|---|
| Broker (auth flow, MFA modes, desktop choice, tokens, back-end drivers) | implemented; 28 unit/protocol tests |
| Proxy module | implemented; end-to-end tested in real freerdp-proxy 3.32.1 (TLS + Kerberos NLA) |
| PAM token module | implemented; functional test through libpam |
| Ansible roles | implemented; `ansible-lint` production profile passes; templates render and are accepted by broker and proxy |
| xrdp/X11 desktops, GNOME headless, Plasma headless | deployed by the roles; **need validation on a lab host** (see docs/desktop-matrix.md) |
| Phase 4 tooling (rdpbench, perfload, session_report, tuning role) | implemented and tested; proxy overhead measured (no fps loss, ~0.3–0.5 % core per Mbit/s) |
| Phase 4 GPU validation (Intel/AMD/NVIDIA) | **needs GPU hosts**, see the runbook in docs/performance.md |
| Smartcard pre-logon, web/Guacamole path, wlroots desktops, xrdp HW encoder | phase 5 / not supported yet |
