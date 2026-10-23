# fastrdp – multi-user Linux RDP terminal server

A Windows-RDS-style terminal server for Linux, built from maintained parts:

- **One front-end:** `freerdp-proxy3` with Kerberos NLA, plus a small module that
  asks a session broker before letting anyone in.
- **MFA:** privacyIDEA (TOTP/HOTP, YubiKey OTP, push), shared with Keycloak.
- **All common desktops:**
  - X11 desktops (Xfce, MATE, Cinnamon, LXQt, Plasma X11) through **xrdp 0.10.6.1**
    with H.264, on the GPU via fastrdp's FFmpeg encoder (VA-API, NVENC, QSV).
  - **GNOME 50** through GDM headless sessions + gnome-remote-desktop.
  - **Plasma 6 Wayland** through KWin's virtual backend + KRdp.
  - **Sway, labwc, Wayfire** (wlroots) nested in an xrdp session, so they keep
    xrdp's H.264 path.
- **GPU where possible:**
  - glamor rendering on Intel/AMD.
  - VA-API/NVENC H.264 in the Wayland back-ends and, through fastrdp's patched xrdp,
    in X11 sessions.
  - VirtualGL on NVIDIA.

**Start here:** [docs/quickstart.md](docs/quickstart.md) (guided setup, preflight,
first connection), without Ansible: [docs/manual-setup.md](docs/manual-setup.md) ·
Back-ends: [docs/backends/](docs/backends/README.md) · Tests: [tests/README.md](tests/README.md)

Plan: [docs/plan.md](docs/plan.md), backlog: [docs/backlog.md](docs/backlog.md) · Design: [docs/architecture.md](docs/architecture.md) ·
Auth/MFA: [docs/auth-matrix.md](docs/auth-matrix.md) · Desktops/GPU:
[docs/desktop-matrix.md](docs/desktop-matrix.md) · Performance: [docs/performance.md](docs/performance.md) ·
Clients: [docs/client-guide.md](docs/client-guide.md), Windows/Kerberos: [docs/windows-clients.md](docs/windows-clients.md) · Web: [docs/web-access.md](docs/web-access.md), approval notifications: [docs/notifications.md](docs/notifications.md) ·
Smartcard/NLA: [docs/smartcard-nla.md](docs/smartcard-nla.md) · Passkeys/FIDO2: [docs/passkeys.md](docs/passkeys.md), WebAuthn redirection (research): [docs/webauthn-redirection.md](docs/webauthn-redirection.md) · Kerberized NFS homes: [docs/nfs-kerberos-homes.md](docs/nfs-kerberos-homes.md) · Kerberized SMB homes: [docs/smb-kerberos-homes.md](docs/smb-kerberos-homes.md) · Upstream reports: [docs/upstream.md](docs/upstream.md) · Packages/APT repository: [docs/packaging.md](docs/packaging.md) · Vendored dependencies: [docs/vendoring.md](docs/vendoring.md)

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
ansible/              roles: common (site-wide defaults + checks) base identity gpu desktops tuning xrdp
                      gnome_rd plasma_krdp mfa_privacyidea broker freerdp_proxy web_gateway;
                      preflight.yml (read-only target checks)
scripts/              fastrdp-setup (guided inventory generator) + tests
tests/                (inventory and CI map: tests/README.md)
  ansible/            role templates rendered and parsed; site checks of role common
  packaging/          fetch/build-key/CI/publish script tests, post-install checks
  proxy-e2e/          real freerdp-proxy + module end-to-end tests (TLS, Kerberos NLA, smartcard/PKINIT)
  smoke/              checks for a deployed host
  perf/               rdpbench (headless benchmark client), perfload, proxy-overhead/compare scripts
  gpu/                session_report.py: which renderer/H.264 encoder a session really uses
  wlroots/            wlroots-in-x launcher tests (Sway, labwc, Wayfire on Xvfb)
  krb5-spnego/        is MIT krb5 affected by the SPNEGO mechListMIC regression? (WinPR -> MIT)
third_party/          vendored dependencies: sources.yml (versions, sha256), fetch.sh, build scripts
                      (docs/vendoring.md); FreeRDP -> /opt/fastrdp, xrdp + xorgxrdp
patches/xrdp/         FFmpeg hardware H.264 encoder for xrdp 0.10.6.1 (+ functional test)
patches/freerdp/      PKCS#11 slot id fix for client-side smartcard logon
patches/krb5/         MIT SPNEGO mechListMIC fix (reference only, krb5 is not vendored)
```

## Deploy

Target: Ubuntu 26.04 or Debian 13, joined to Samba AD / FreeIPA (or a keytab
provided). Full walk-through, production checklist and troubleshooting:
[docs/quickstart.md](docs/quickstart.md).

```sh
make setup                          # guided: asks ~15 questions, writes ansible/inventories/<name>/
make preflight INVENTORY=<name>     # read-only checks of the target (DNS, time, KDC, ports, GPU, ...)
make deploy INVENTORY=<name>        # ansible-playbook site.yml
sudo tests/smoke/check-host.sh alice                         # on the host
xfreerdp3 /v:rdp1.lab.example.com /u:alice /d:LAB.EXAMPLE.COM /sec:nla /gfx:avc444
```

Every role variable has a default (site-wide ones in `ansible/roles/common`); an
inventory needs only `fastrdp_realm` and `fastrdp_domain` plus what differs. The
`common` role refuses inconsistent settings before anything is changed.

## Tests

```sh
make test          # unit + protocol tests (broker, webgate, PAM, GPU report, setup), lint
make test-all      # + build/CI/publish script tests, Ansible template rendering
make test-e2e test-e2e-nla test-e2e-smartcard   # real freerdp-proxy; FREERDP_PREFIX=/opt/fastrdp
```

What each test guards and where CI runs it: [tests/README.md](tests/README.md).

## Status

| Area | State |
|---|---|
| Broker (auth flow, MFA modes, desktop choice, tokens, back-end drivers) | implemented; 561 unit/protocol tests incl. regression tests for review findings |
| Proxy module | implemented; end-to-end tested in real freerdp-proxy (TLS, Kerberos NLA, smartcard, back-end certificate pinning, waiting screen, desktop picker) against fastrdp's FreeRDP 3.32.2, in CI; code field of `code_or_web` and the lab-only input trace unit-tested (also with sanitizers), not yet run in a proxy session |
| Windows mstsc | Kerberos NLA (user-to-user) **confirmed in the field** with an AD-joined host; waiting screen, desktop picker, web approval and the code field with mstsc / Windows App to validate ([lab plan](docs/lab-waiting-screen-input.md)) ([docs/windows-clients.md](docs/windows-clients.md)) |
| Second factor | modes `none`, `push`, `otp`, `otp_or_push`, `web`, `push_or_web`, `code_or_web` ([docs/auth-matrix.md](docs/auth-matrix.md)): privacyIDEA push/OTP, web approval after a Keycloak passkey sign-in (login-bound QR code, login code), waiting screen in the RDP window; TOTP typed on the waiting screen and checked by Keycloak (`code_or_web`: direct grant without password, clean refusal for users without TOTP, `amr` safeguard; real clients to validate, not yet offered by `fastrdp-setup`); skip from KDC evidence (smartcard, Windows Hello for Business) implemented, real AD to validate |
| Notifications (ntfy, Web Push) | implemented and checked against the RFC test vector and local servers ([docs/notifications.md](docs/notifications.md)); real devices to validate |
| PAM token module | implemented; functional test through libpam |
| Ansible roles | implemented and used for field deployments; `ansible-lint` production profile passes; templates render and are accepted by broker and proxy |
| xrdp/X11 desktops, GNOME headless, Plasma headless | deployed by the roles; **need validation on a lab host** (see docs/desktop-matrix.md) |
| Phase 4 tooling (rdpbench, perfload, session_report, tuning role) | implemented and tested; proxy overhead measured (no fps loss, ~0.3–0.5 % core per Mbit/s) |
| Phase 4 GPU validation (Intel/AMD/NVIDIA) | **needs GPU hosts**, see the runbook in docs/performance.md |
| Web path (Keycloak + Guacamole, role `web_gateway`) | implemented; webgate flow and Guacamole crypto tested (byte-identical to Guacamole's reference); Keycloak passkey flow (`acr=mfa`) and the code check of `code_or_web` tested end to end against Keycloak 26.8.1 (50 checks); Guacamole containers need a lab run |
| Smartcard (PKINIT) logon through the proxy | works with a software token end to end; PIN-leak bug fixed; real cards/AD to validate |
| xrdp PR #3868 (NLA) | assessed: FreeRDP default clients fail because of an MIT krb5 1.21–1.22.1 bug (fixed in 1.22.2); no smartcards; proxy stays the NLA point |
| wlroots desktops (Sway, labwc, Wayfire) | implemented; launcher tested with all three on Xvfb (15 checks); full xrdp session to validate. Hyprland not supported (no X11 backend) |
| Audio and microphone (PipeWire + `pipewire-module-xrdp`) | implemented; real clients to validate ([docs/audio.md](docs/audio.md)) |
| xrdp hardware H.264 (FFmpeg: VA-API, NVENC, QSV) | patch for xrdp 0.10.6.1 (`patches/xrdp/`) in fastrdp's xrdp build; tested via libx264 through the same code path and the no-GPU fallback, in CI; real GPUs to validate |
| Packaging | Debian/Ubuntu packages incl. vendored FreeRDP/xrdp, signed APT repository on GitHub Pages, live: `*-stable` = latest release tag, `*-testing` = latest `main` ([docs/packaging.md](docs/packaging.md)) |
| Setup | guided assistant, read-only preflight, quick start ([docs/quickstart.md](docs/quickstart.md)); not yet run against a real target |

## License

Apache License 2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). The vendored FreeRDP and
xrdp packages link the distributions' GPL-licensed FFmpeg/x264 and are therefore
distributed under GPL-3.0-or-later terms, with their corresponding source published
next to the APT repository. Details: [docs/licensing.md](docs/licensing.md).
