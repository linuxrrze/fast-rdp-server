# Audio and microphone redirection

Do sessions play sound on the client, and can applications in the session use the
client's microphone?

**Short answer:** not as deployed today, on any back-end. The proxy is not the problem:
freerdp-proxy passes every audio channel through unchanged. What is missing is on the
session side:

| Back-end | Audio out today | Microphone today | With the changes below |
|---|---|---|---|
| xrdp (xfce, mate, cinnamon, lxqt, plasma-x11) | no | no | both |
| wlroots-in-x (sway, labwc, wayfire) | no | no | both, plus one launcher line |
| GNOME 50 (gnome-remote-desktop headless) | probably silent on hosts without a sound card [inferred] | probably works when the client opts in [untested] | audio out with `pipewire-pulse` |
| Plasma 6 (KRdp) | no | no | not possible without new KRdp code: use `plasma-x11` (xrdp) for audio |

Nothing about audio has been tested through fastrdp yet. The findings below come from
the sources of the versions fastrdp ships (xrdp 0.10.6.1, FreeRDP 3.32.2,
gnome-remote-desktop 50.2, KRdp 6.3.5/6.6.4/6.8.1, pipewire-module-xrdp 0.2,
guacamole-server 1.6.0) and from the Debian 13 / Ubuntu 26.04 package metadata.
The changes are backlog item A1 ([backlog.md](backlog.md)).

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
- **Today:** no role installs the module, and with `install_recommends: false`
  (`roles/desktops`) usually no PipeWire either (`xfce4` pulls only `libpulse0`).
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
- `PULSE_SCRIPT` in `sesman.ini` belongs to the PulseAudio module and can go.

### wlroots desktops (sway, labwc, wayfire in xorgxrdp)

As xrdp, but these compositors do not run XDG autostart (`wlroots-in-x`), so the
launcher must start `/usr/libexec/pipewire-module-xrdp/load_pw_modules.sh` itself when
it exists.

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
  by default (a dummy sink when none exists) and fixes both.
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
    caveat above);
  - xrdp: `rdpsnd=false` turns audio out off; there is no microphone-only switch
    (`XRDP_NO_RDPSND_REC` only affects the legacy rdesktop path); loading the PipeWire
    module sink-only (a commented variant in `load_pw_modules.sh`) leaves the microphone
    unused per host;
  - g-r-d: none.
- **Per user or group: nothing today.** Possible in the fastrdp proxy module through the
  proxy's channel filter hooks, with the broker returning a "microphone allowed" flag.
  New code, needs a lab.

## Client settings

| Client | Audio out | Microphone |
|---|---|---|
| mstsc / `.rdp` | `audiomode:i:0` play on this computer (`1` on the remote computer, `2` off); `audioqualitymode:i:0\|1\|2` dynamic, medium, high | `audiocapturemode:i:1` |
| Windows App, Remmina | same channels ("Audio output: local"; "Redirect local microphone") [not verified through fastrdp] | same |
| FreeRDP 3 | `/sound[:sys:pulse\|alsa\|fake,...]` (static and dynamic rdpsnd); `/audio-mode:0\|1\|2` redirect, server, none | `/microphone[:sys:pulse,dev:...]` |
| Guacamole 1.6.0 (web path) | on by default (static `rdpsnd`, PCM) | `enable-audio-input: "true"` in `fastrdp_web_rdp_parameters` (not set today), HTTPS and the browser's permission |

FreeRDP's `/drive` and `/smartcard` load `rdpsnd sys:fake` on their own. On the web
path xrdp works once fixed; g-r-d should work through its `rdpsnd` fallback
[unverified]; KRdp has nothing.

## Changes needed (backlog A1)

1. **Roles:** `xrdp` (or `desktops`): runtime packages `pipewire`, `wireplumber`,
   `pipewire-pulse`, `pipewire-module-xrdp` (optionally `pulseaudio-utils`); `gnome_rd`:
   `pipewire-pulse`. Optional `fastrdp_audio_input: true|false` driving the proxy's
   `AudioInput` and a sink-only xrdp module load.
2. **Launcher:** `broker/session/libexec/wlroots-in-x` starts `load_pw_modules.sh` when it
   exists.
3. **Web gateway:** document `enable-audio-input` in `fastrdp_web_rdp_parameters`, or a
   `fastrdp_web_audio_input` switch.
4. **Docs:** the client settings above in client-guide, windows-clients and
   freerdp-client; the per-back-end audio rows once tested.
5. **Tests:**
   - The test FreeRDP build (`third_party/build-freerdp.sh`) has PulseAudio, ALSA and OSS
     off: only the `fake` playback backend and no microphone backend. It can show that
     `rdpsnd` negotiates, not the microphone.
   - Host smoke test: distribution `xfreerdp3` with PipeWire, `/sound:sys:pulse` into a
     null sink and `/microphone:sys:pulse,dev:<null-sink monitor or a sine source>`;
     on the server `pw-cli ls Node` shows `xrdp-sink`/`xrdp-source` or
     `grd_remote_audio_source`, `pw-record` from the source is not silent, the chansrv log
     names the negotiated format.
   - Proxy e2e: a stub back-end that opens `AUDIO_INPUT` and checks the client's create
     response; lab S10 with `AudioInput=false`.

## Open questions (lab)

- Which codecs mstsc and the Windows App advertise (AAC, MP3).
- Whether Ubuntu's FreeRDP DSP encodes AAC for g-r-d.
- That GNOME has no sink without `pipewire-pulse` (inferred, not observed).
- g-r-d's `rdpsnd` fallback with Guacamole.
- Behaviour with `AudioInput=false` (dropped create request).
- Audio after an xrdp reconnect; latency and A/V sync.
- Windows App and Remmina through the proxy.
