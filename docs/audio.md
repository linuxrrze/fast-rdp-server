# Audio and microphone redirection

Do sessions play sound on the client, and can applications in the session use the
client's microphone?

**Short answer:** yes on xrdp, wlroots and GNOME desktops, since backlog item A1
([backlog.md](backlog.md)); **implemented, not yet tested on a host with real clients**.
The proxy was never the problem: freerdp-proxy passes every audio channel through
unchanged. The roles now install what the session side needs:

| Back-end | Audio out | Microphone | Before A1 |
|---|---|---|---|
| xrdp (xfce, mate, cinnamon, lxqt, plasma-x11) | yes (`xrdp-sink`) | yes (`xrdp-source`), unless `fastrdp_audio_input: false` | neither: no role installed the PipeWire module |
| wlroots-in-x (sway, labwc, wayfire) | as xrdp; `wlroots-in-x` starts the module | as xrdp | neither |
| GNOME 50 (gnome-remote-desktop headless) | yes, with `pipewire-pulse` (a sink also without a sound card) | when the client opts in [untested]; no server switch | probably silent on hosts without a sound card [inferred] |
| Plasma 6 (KRdp) | no | no | not possible without new KRdp code: use `plasma-x11` (xrdp) for audio |

The findings below come from the sources of the versions fastrdp ships (xrdp 0.10.6.1,
FreeRDP 3.32.2, gnome-remote-desktop 50.2, KRdp 6.3.5/6.6.4/6.8.1, pipewire-module-xrdp
0.2, guacamole-server 1.6.0) and from the Debian 13 / Ubuntu 26.04 package metadata.
What fastrdp does with them: [Implementation](#implementation-backlog-a1); how to check a
host: [Verifying on a host](#verifying-on-a-host).

## Channels

| Direction | RDP channel | Spec |
|---|---|---|
| Audio out | static `rdpsnd`; dynamic `AUDIO_PLAYBACK_DVC`, `AUDIO_PLAYBACK_LOSSY_DVC` (UDP only) | MS-RDPEA |
| Microphone | dynamic `AUDIO_INPUT` | MS-RDPEAI |

The client decides: audio out goes to the client only when it asks for it ("play on this
computer"), and the microphone channel exists only when the client offers it ("record
from this computer").

## Back-ends

### xrdp (X11 desktops)

- **Audio out:** static `rdpsnd` only (xrdp has no playback DVC). Codec preference in
  chansrv: AAC (not built), Opus, MP3, PCM; fastrdp's xrdp build has Opus and MP3
  (`--enable-opus --enable-mp3lame`, `third_party/build-xrdp.sh`)
  (xrdp `sesman/chansrv/sound.c:180-194`, `861-879`).
- **Microphone:** `AUDIO_INPUT`, PCM 44.1 kHz stereo only, about 1.4 Mbit/s upstream
  (`sesman/chansrv/audin.c`).
- **Needed:** the PipeWire module `pipewire-module-xrdp` (0.2-2 in trixie, 0.2-2build1 in
  resolute universe) plus `pipewire`, `wireplumber`, `pipewire-pulse` (and optionally
  `pulseaudio-utils` for `pactl`). The module depends neither on xrdp nor on xrdp's
  source tree (it copies the protocol constants), so it works with `fastrdp-xrdp`.
  `pulseaudio-module-xrdp` needs the PulseAudio source tree, is not packaged and is not
  needed: both distributions use PipeWire.
- **Before A1** no role installed the module, and with `install_recommends: false`
  (`roles/desktops`) usually no PipeWire either (`xfce4` pulls only `libpulse0`). Now
  the xrdp role installs them (`fastrdp_xrdp_audio_packages`).
- **How it works once installed:**
  - sesexec exports `XRDP_SESSION`, `XRDP_SOCKET_PATH=/run/xrdp/sockdir/<uid>`,
    `XRDP_PULSE_SINK_SOCKET` and `XRDP_PULSE_SOURCE_SOCKET` (xrdp
    `sesman/sesexec/env.c:175-187`).
  - They reach the desktop through `startwm.sh` and `dbus-run-session`. The XDG autostart
    entry `/etc/xdg/autostart/pipewire-xrdp.desktop` runs `load_pw_modules.sh`, which
    loads `libpipewire-module-xrdp` in a `pw-cli` process with that environment,
    talking to the user's socket-activated PipeWire (`pam_systemd` is in the
    `xrdp-sesman` PAM stack, so the user manager exists).
  - The script also sets user-wide PipeWire settings (quantum 2048, rate 44100) and makes
    xrdp-sink/xrdp-source the defaults with `pactl`. That also affects a GNOME session
    of the same user running at the same time.
  - Outside xrdp sessions the script exits quietly, so it is harmless for GNOME/Plasma.
- The module creates the source only when the load names `source.stream.props`
  (`src/module-xrdp.c:961-964`, `MODE_XRDP_SOURCE`); without it, xrdp-sink alone. The
  script carries this sink-only load as a comment.
- `PULSE_SCRIPT` in `sesman.ini` belongs to the PulseAudio module; fastrdp's template
  no longer sets it.
- The package installs `/usr/libexec/pipewire-module-xrdp/load_pw_modules.sh` and
  `/etc/xdg/autostart/pipewire-xrdp.desktop` (`debian/pipewire-module-xrdp.install`) and
  only suggests `pipewire-bin`, which has the `pw-cli` and `pw-metadata` the script
  needs.

### wlroots desktops (sway, labwc, wayfire in xorgxrdp)

As xrdp, but these compositors do not run XDG autostart, so `wlroots-in-x` starts the
loader itself (`/usr/libexec/fastrdp/xrdp-audio`, which runs
`/usr/libexec/pipewire-module-xrdp/load_pw_modules.sh` when it exists).

### GNOME (gnome-remote-desktop headless)

- **Audio out:** dynamic `AUDIO_PLAYBACK_DVC` with a fallback to static `rdpsnd`; AAC,
  Opus, PCM; available since g-r-d 43 (`src/grd-rdp-dvc-audio-playback.c`).
- **Microphone:** `AUDIO_INPUT` since g-r-d 46; creates the PipeWire source
  `grd_remote_audio_source` (`src/grd-rdp-dvc-audio-input.c`).
- g-r-d depends on `pipewire` and `wireplumber`, not on `pipewire-pulse`. It only
  captures from an existing Audio/Sink (`grd-rdp-dvc-audio-playback.c:1229-1230`). On a
  host without a sound card (VMs) nothing creates one, and applications using the
  PulseAudio API find no server, so audio out is **probably silent** [inferred from code
  and package dependencies, not observed]. `pipewire-pulse` loads `module-always-sink`
  by default (a dummy sink when none exists) and fixes both; the gnome_rd role installs
  it.
- No g-r-d setting or `grdctl` key turns audio on or off.

### Plasma (KRdp)

KRdp turns playback off and has "TODO: Implement audio support"
(`src/RdpConnection.cpp`, 6.3.5 to 6.8.1). No audio and no microphone; users who need
audio choose `plasma-x11` (xrdp).

## Proxy (freerdp-proxy 3.32.2)

- **Everything passes through today.** `pf_utils_is_passthrough()` always returns TRUE
  (`server/proxy/pf_utils.c:76-82`). With `PassthroughIsBlacklist=true` and an empty list
  the static `rdpsnd` channel passes when `AudioOutput=true`, and `drdynvc` is passed
  through untouched as long as GFX, AudioOutput, AudioInput, Multitouch,
  VideoRedirection and CameraRedirection are all true, which is fastrdp's `proxy.ini`.
  The proxy does no format negotiation, decoding or transcoding.
- The proxy's own `rdpsnd sys:fake` is loaded only outside passthrough mode, so never
  here (`pf_client.c:105-123`).
- The proxy tells the back-end that playback and capture are enabled whatever the
  client said (`pf_client.c:217-218`). Harmless: the microphone only flows when the
  client opens its `AUDIO_INPUT` listener, so the client's opt-in still decides.
- The lossy playback channel needs UDP, which the proxy does not offer.
- `AudioInput=false` / `AudioOutput=false` block the channels but switch the whole
  `drdynvc` into intercept mode (`pf_context.c:60-84`), a less tested path that also
  carries GFX (lab S10 in [rdp-spec-conformance.md](rdp-spec-conformance.md)). A
  blocked `AUDIO_INPUT` create request is silently dropped
  (`channels/pf_channel_drdynvc.c:431-433`); how xrdp and g-r-d react is untested (g-r-d
  has a 10 s protocol timeout).

## Privacy and policy

- The client always opts in to the microphone (mstsc `audiocapturemode:i:1`, FreeRDP
  `/microphone`, Guacamole `enable-audio-input`).
- Server-side switches that exist:
  - proxy, all users: `[Channels] AudioInput=false` / `AudioOutput=false` (intercept-mode
    caveat above); **not wired to any fastrdp setting** (see below);
  - xrdp: `rdpsnd=false` turns audio out off (`fastrdp_audio: false`); there is no
    microphone-only switch in xrdp (`XRDP_NO_RDPSND_REC` only affects the legacy
    rdesktop path); loading the PipeWire module sink-only (the commented variant in
    `load_pw_modules.sh`) leaves the microphone unused per host
    (`fastrdp_audio_input: false`);
  - g-r-d: none;
  - Guacamole (web path): `enable-audio-input` (from `fastrdp_audio_input`);
  - the `.rdp` files of the web gateway's chooser page: `audiomode` and
    `audiocapturemode` (from `fastrdp_audio`, `fastrdp_audio_input`; below).
- `fastrdp_audio_input: false` is a **default, not a policy**: the module runs in the
  user's own PipeWire, so a user can load it with a source again (`pw-cli load-module
  libpipewire-module-xrdp source.stream.props=...`), and GNOME sessions keep their
  microphone. Enforcing it needs the proxy's `AudioInput=false` (lab S10 first) or the
  per-user module code below.
- **Per user or group: nothing today.** Possible in the fastrdp proxy module through the
  proxy's channel filter hooks, with the broker returning a "microphone allowed" flag.
  New code, needs a lab.

## Client settings

| Client | Audio out | Microphone |
|---|---|---|
| mstsc / `.rdp` | `audiomode:i:0` play on this computer (`1` on the remote computer, `2` off); `audioqualitymode:i:0\|1\|2` dynamic, medium, high. Downloaded from the chooser page: `0`, or `2` with `fastrdp_audio: false` | `audiocapturemode:i:1` (mstsc's default is `0`). Downloaded from the chooser page: `1` with `fastrdp_audio` and `fastrdp_audio_input`, else `0` |
| Windows App, Remmina | same channels ("Audio output: local"; "Redirect local microphone") [not verified through fastrdp] | same |
| FreeRDP 3 | `/sound[:sys:pulse\|alsa\|fake,...]` (static and dynamic rdpsnd); `/audio-mode:0\|1\|2` redirect, server, none | `/microphone[:sys:pulse,dev:...]` |
| Guacamole 1.6.0 (web path) | on by default (static `rdpsnd`, PCM) | `enable-audio-input`, set from `fastrdp_audio_input` (an entry in `fastrdp_web_rdp_parameters` wins); HTTPS and the browser's permission |

FreeRDP's `/drive` and `/smartcard` load `rdpsnd sys:fake` on their own. On the web
path xrdp works once fixed; g-r-d should work through its `rdpsnd` fallback
[unverified]; KRdp has nothing.

## Implementation (backlog A1)

Status: **implemented, not yet tested on a host.** Settings in `roles/common`:

| Setting | Default | Effect |
|---|---|---|
| `fastrdp_audio` | `true` | xrdp role: `fastrdp_xrdp_audio_packages` (`pipewire`, `pipewire-bin`, `wireplumber`, `pipewire-pulse`, `pipewire-module-xrdp`, `pulseaudio-utils`; no recommends), fastrdp's loader; `xrdp.ini` `rdpsnd=true`. gnome_rd role: `pipewire-pulse`. `false`: nothing installed (packages from earlier runs stay), `rdpsnd=false`, `.rdp` downloads `audiomode:i:2` and `audiocapturemode:i:0` (`webgate.toml` `rdp_audio = false`) |
| `fastrdp_audio_input` | `true` | `false`: `sesman.ini` `[SessionVariables] FASTRDP_AUDIO_INPUT=false`, the module loaded sink-only, the package's autostart entry hidden; Guacamole `enable-audio-input: "false"`; `.rdp` downloads `audiocapturemode:i:0` (`webgate.toml` `rdp_audio_input = false`). The proxy is unchanged |

`pipewire-module-xrdp` is in Debian 13 main and Ubuntu 26.04 universe (as with
`python3-kdcproxy`, the roles expect universe to be enabled).

**How the module is loaded.** `/usr/libexec/fastrdp/xrdp-audio` (`fastrdp-session`, or
copied by the xrdp role) runs the package's `load_pw_modules.sh`:
- from `wlroots-in-x` in wlroots sessions;
- from `/etc/xdg/autostart/fastrdp-xrdp-audio.desktop` (`--autostart`) in other
  sessions, but only while the package's own entry `pipewire-xrdp.desktop` is hidden;
  otherwise that entry loads it, as upstream intends;
- outside xrdp sessions (`XRDP_SESSION` unset: GNOME, Plasma) and without the package
  it does nothing.

With `FASTRDP_AUDIO_INPUT=false` it puts itself first in `PATH` as `pw-cli` for the
script: that shim drops `source.stream.props=` from the `load-module
libpipewire-module-xrdp` call and passes every other `pw-cli` call on. The script's own
logic (removing old xrdp nodes, quantum and rate, default sink via `pactl`) stays
upstream's; `pactl set-default-source xrdp-source` then fails harmlessly. The role sets
`Hidden=true` in the package's `pipewire-xrdp.desktop` only in this mode, so the module
is never loaded twice. That is a local change of a conffile: dpkg keeps it on upgrades
(it asks when the packaged file changes), and the next role run restores it.

**Why sink-only and not the proxy's `AudioInput=false`.** Turning a channel off in
`proxy.ini` moves the whole `drdynvc` (which also carries GFX/H.264, display control
and the other dynamic channels) from passthrough into the proxy's intercept mode, which
fastrdp has not tested (lab S10), and what xrdp and g-r-d do with the silently dropped
`AUDIO_INPUT` create request is unknown. Sink-only keeps the proxy as it is, matches a
variant upstream ships, and covers the X11 and wlroots desktops; its limits (a default,
not a policy; GNOME unaffected) are listed under
[Privacy and policy](#privacy-and-policy).

**Web path.** `webgate.toml` gets `enable-audio-input` from `fastrdp_audio_input` unless
`fastrdp_web_rdp_parameters` sets it; audio out stays Guacamole's default (on). YAML
booleans there reach Guacamole as `"true"`/`"false"`.

**`.rdp` downloads** (chooser page, [web-access.md](web-access.md#rdp-apps)): mstsc
plays sound by default but never records, so the files carry both lines, from
`webgate.toml` `[webgate] rdp_audio` (`fastrdp_audio`) and `rdp_audio_input`
(`fastrdp_audio` and `fastrdp_audio_input`):

| `fastrdp_audio` | `fastrdp_audio_input` | `.rdp` lines |
|---|---|---|
| `true` | `true` | `audiomode:i:0`, `audiocapturemode:i:1` |
| `true` | `false` | `audiomode:i:0`, `audiocapturemode:i:0` |
| `false` | any | `audiomode:i:2`, `audiocapturemode:i:0` |

With `fastrdp_audio: false` the server has no sound (`rdpsnd=false`, nothing installed),
so the file says "do not play" (`2`) instead of leaving mstsc's default "play on this
computer", which would only open an empty channel. The lines are the same for every
desktop: a Plasma (Wayland) session simply has no sound. Users can still change them in
mstsc (Show Options → Local Resources) before connecting.

**Plasma (KRdp):** nothing to do; users who need sound choose `plasma-x11`.

**Tests** ([tests/README.md](../tests/README.md)):
- `tests/ansible/test_templates.py` (`Audio`): `rdpsnd`, `FASTRDP_AUDIO_INPUT` and no
  `PULSE_SCRIPT` per switch, Guacamole `enable-audio-input` (default, off, own value),
  `webgate.toml` `rdp_audio`/`rdp_audio_input` (default, no microphone, no audio),
  packages and tasks per switch, packaging, the common checks; `xrdp-audio` with a stub
  `load_pw_modules.sh` and `pw-cli` (with microphone, sink-only, other modules untouched,
  nothing outside xrdp sessions, autostart only while the package's entry is hidden).
- `tests/wlroots/run.sh`: `wlroots-in-x` starts the loader (stub).
- `tests/smoke/check-audio.sh`: read-only host check, below.
- Not automated: the test FreeRDP build (`third_party/build-freerdp.sh`) has PulseAudio,
  ALSA and OSS off (only the `fake` playback back-end, no microphone back-end), so it can
  show that `rdpsnd` negotiates, not the microphone. A proxy e2e with a stub back-end
  that opens `AUDIO_INPUT`, and lab S10 with `AudioInput=false`, remain open.

## Verifying on a host

1. Deploy with the defaults; connect with "play on this computer" and "record from this
   computer" (mstsc `audiomode:i:0`, `audiocapturemode:i:1`; FreeRDP `/sound:sys:pulse
   /microphone:sys:pulse`), once per desktop type.
2. `sudo tests/smoke/check-audio.sh USER` (or `tests/smoke/check-audio.sh` in a session
   terminal): packages, `rdpsnd`, autostart entries, PipeWire and WirePlumber in the
   user manager, the nodes (`xrdp-sink`, `xrdp-source`, or `grd_remote_audio_source` on
   GNOME) and the default sink.
3. Play something in the session (`speaker-test -c2 -t wav` from `alsa-utils`, or any
   media player) and record (`pw-record --target xrdp-source /tmp/mic.wav`, GNOME:
   `--target grd_remote_audio_source`); the recording must not be silent.
   `journalctl -t xrdp-chansrv` names the negotiated format.
4. With a client without a sound device: distribution `xfreerdp3` with PipeWire,
   `/sound:sys:pulse` into a null sink and `/microphone:sys:pulse,dev:<null-sink
   monitor or a sine source>`.
5. `fastrdp_audio_input: false`: no `xrdp-source` after a new login; the web path does
   not offer the microphone; an `.rdp` file downloaded from the chooser page says
   `audiocapturemode:i:0`.

## Open questions (lab)

- Everything above on a real host: xrdp, wlroots and GNOME sessions with mstsc, the
  Windows App, FreeRDP, Remmina and the browser.
- The sink-only load in a real session (`FASTRDP_AUDIO_INPUT=false`), and that the
  desktops honour `Hidden=true` in the package's autostart entry (XDG autostart spec;
  xfce4-session, mate-session, cinnamon-session, lxqt-session, plasma-x11).
- Which codecs mstsc and the Windows App advertise (AAC, MP3).
- Whether Ubuntu's FreeRDP DSP encodes AAC for g-r-d.
- That GNOME has no sink without `pipewire-pulse` (inferred, not observed).
- g-r-d's `rdpsnd` fallback with Guacamole.
- Behaviour with `AudioInput=false` (dropped create request).
- Audio after an xrdp reconnect; latency and A/V sync.
- Windows App and Remmina through the proxy.
