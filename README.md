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
  - **Sway, labwc, Wayfire** (wlroots) nested in an xrdp session, so they keep
    xrdp's H.264 path.
- **GPU where possible:**
  - glamor rendering on Intel/AMD.
  - VA-API/NVENC H.264 in the Wayland back-ends.
  - VirtualGL on NVIDIA.

Plan: [docs/plan.md](docs/plan.md) · Design: [docs/architecture.md](docs/architecture.md) ·
Auth/MFA: [docs/auth-matrix.md](docs/auth-matrix.md) · Desktops/GPU:
[docs/desktop-matrix.md](docs/desktop-matrix.md) · Performance: [docs/performance.md](docs/performance.md) ·
Clients: [docs/client-guide.md](docs/client-guide.md) · Web: [docs/web-access.md](docs/web-access.md) ·
Smartcard/NLA: [docs/smartcard-nla.md](docs/smartcard-nla.md) · Upstream reports: [docs/upstream.md](docs/upstream.md) · Packages/APT repository: [docs/packaging.md](docs/packaging.md) · Vendored dependencies: [docs/vendoring.md](docs/vendoring.md)

## Layout

```
broker/
  brokerd/            fastrdp-brokerd (Python 3.11+, stdlib only) + unit/protocol tests
  proxy-module/       freerdp-proxy3 module (C, CMake)
  pam_fastrdp_token/  PAM module: xrdp accepts only one-time broker tokens (C) + functional test
  webgate/            fastrdp-webgate: Keycloak OIDC login -> one-time token -> Guacamole (Python)
  session/            systemd units, PAM stacks, session launchers (startwm.sh, session-plasma)
debian/               Debian/Ubuntu packaging of fastrdp itself (docs/packaging.md)
packaging/            vendored FreeRDP/xrdp packaging, CI helper scripts, APT repository (reprepro)
ansible/              roles: base identity gpu desktops xrdp gnome_rd plasma_krdp mfa_privacyidea broker freerdp_proxy
tests/
  proxy-e2e/          real freerdp-proxy + module end-to-end tests (TLS, Kerberos NLA, smartcard/PKINIT)
  smoke/              checks for a deployed host
  perf/               rdpbench (headless benchmark client), perfload, proxy-overhead/compare scripts
  gpu/                session_report.py: which renderer/H.264 encoder a session really uses
  wlroots/            wlroots-in-x launcher tests (Sway, labwc, Wayfire on Xvfb)
  krb5-spnego/        is MIT krb5 affected by the SPNEGO mechListMIC regression? (WinPR -> MIT)
third_party/          vendored dependencies: sources.yml (versions, sha256), fetch.sh, build scripts
                      (docs/vendoring.md); FreeRDP -> /opt/fastrdp, xrdp + xorgxrdp
patches/xrdp/         FFmpeg hardware H.264 encoder for xrdp 0.10.6.1 (+ functional test)
patches/freerdp/      PKCS#11 slot id fix for smartcard logon
patches/krb5/         MIT SPNEGO mechListMIC fix (reference only, krb5 is not vendored)
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
make test-e2e      # needs freerdp-proxy + freerdp3-dev + libcjson-dev, or FREERDP_PREFIX=/opt/fastrdp
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
| Web path (Keycloak + Guacamole, role `web_gateway`) | implemented; webgate flow and Guacamole crypto tested (byte-identical to Guacamole's reference); containers/Keycloak need a lab run |
| Smartcard (PKINIT) logon through the proxy | works with a software token end to end; PIN-leak bug fixed; real cards/AD to validate |
| xrdp PR #3868 (NLA) | assessed: Kerberos OK only with FreeRDP U2U disabled; no smartcards; proxy stays the NLA point |
| wlroots desktops (Sway, labwc, Wayfire) | implemented; launcher tested with all three on Xvfb (15 checks); full xrdp session to validate. Hyprland not supported (no X11 backend) |
| xrdp hardware H.264 (FFmpeg: VA-API, NVENC, QSV) | patch for xrdp 0.10.6.1 (`patches/xrdp/`), applied by the role; tested via libx264 through the same code path and the no-GPU fallback; real GPUs to validate |
