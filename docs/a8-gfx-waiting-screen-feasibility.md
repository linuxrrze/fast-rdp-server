# A8: waiting screen over GFX, feasibility

Feasibility note for [backlog A8](backlog.md#maybe-later) (the waiting screen drawn over
RDPGFX instead of legacy Bitmap Updates). The problem it would solve is in
[a5-capture-2026-10-26.md](a5-capture-2026-10-26.md): mstsc shows the waiting screen black
on the next *Connect* in the same process after a connection that used the Graphics DVC
(`Microsoft::Windows::RDS::Graphics`), and a reactivation before the panel did not help.
Nothing is built. Source checked: FreeRDP 3.32.2 (upstream tarball) and the module at
0.7.8.

Marks: **[verified: file:function]** was read in the source; **[inferred]** is a
conclusion from reading, from the specs as remembered, or a guess. mstsc behaviour is
unknown wherever it is not marked as seen in the lab.

## Verdict

- **Feasible inside the module, without a new FreeRDP patch**, but not with FreeRDP's
  server channel code (`channels/rdpgfx/server`, WTS DVC API). The module would speak
  drdynvc and RDPGFX itself on the front's `drdynvc` static channel: about 600–900 lines
  of C. Planar encoding and the panel exist already.
- **The payoff is uncertain.** Two things only mstsc can answer: does a panel over GFX
  show in the black C2 case, and does mstsc accept the hand-over (Graphics DVC closed, a
  second drdynvc capabilities exchange, a new Graphics DVC from the back-end) in one
  connection. Nothing in the specs or in FreeRDP answers that for mstsc.
- **A new risk:** if mstsc cannot show legacy output after GFX (the A5 hypothesis), a
  back-end that does not use GFX could be black after a GFX waiting screen in the *same*
  connection [inferred]. So use GFX only for clients that announced it, and only behind
  a switch until the lab shows the behaviour.
- **Effort:** spike 2–3 days (plus one lab run); production 7–10 days plus 2 lab days.
  Matches "Large" in the backlog.
- **Recommendation:** run the spike below, with a lab switch off by default, before the
  GFX-off experiment of A5 is repeated or in the same lab session. Stop if mstsc still
  shows black in C2 with the GFX panel.

## When the waiting screen runs

- The proxy's peer `PostConnect` sets up the front's static channels, creates the
  back-end client context, then asks the module for the target
  [verified: server/proxy/pf_server.c:pf_server_post_connect]. The waiting screen runs
  inside that request (`FILTER_TYPE_SERVER_FETCH_TARGET_ADDR`, the module's
  `fastrdp_fetch_target`) [verified: fastrdp_plugin.c:fastrdp_fetch_target].
- The back-end client thread starts only after the hook returns
  [verified: pf_server.c:pf_server_post_connect]. So everything the module does on
  drdynvc ends before the back-end exists. There is no concurrent back-end traffic.
- The proxy's peer loop (and with it `WTSVirtualChannelManagerCheckFileDescriptor`) does
  not run while `PostConnect` runs [verified: pf_server.c:pf_server_handle_peer]. The
  module reads the client itself with patch 0007, as the picker, the code field and
  `WaitingScreenObserve` do [verified: patches/freerdp/0007,
  fastrdp_plugin.c:ws_picker_read, ws_input_take].
- The module already wraps `peer->ReceiveChannelData` while it reads, in front of the
  proxy's own hook [verified: fastrdp_plugin.c:ws_input_take, ws_picker_channel_data].
  That is where it would take its drdynvc PDUs out.

## How drdynvc reaches the front today

- fastrdp's `proxy.ini` has `PassthroughIsBlacklist=true`, empty `Passthrough` and
  `Intercept`, and all of GFX, audio, multitouch, video and camera on
  [verified: ansible/roles/freerdp_proxy/templates/proxy.ini.j2]. So `drdynvc` is a
  plain pass-through static channel [verified: pf_utils.c:pf_utils_get_channel_mode,
  pf_context.c:StaticChannelContext_new].
- With any of those off (for example `GFX=false` in the A5 experiment) the proxy
  *intercepts* drdynvc instead and tracks the DVCs [verified: pf_context.c:dyn_intercept].
  The tracker passes capabilities both ways, learns channel ids from the back-end's
  Create Requests, and drops front data for ids it does not know
  [verified: channels/pf_channel_drdynvc.c:DynvcTrackerPeekFn, DynvcTrackerHandleCmd].
  A back-end Create that reuses a known id replaces the entry with a warning
  [verified: DynvcTrackerHandleCreateBack].
- In both modes the back-end owns the DVC protocol: its caps request and creates pass to
  the client. The proxy's own WTS channel manager on the front does not take part.
- Front channel data during the wait: the client context already exists then, so the
  proxy's hook hands it to the channel's handler and, on pass-through, queues it for the
  back-end [verified: pf_server.c:pf_server_receive_channel_data_hook,
  pf_client.c:pf_client_send_channel_data]. The queue is sent as soon as the back-end
  connects, before the reactivation [verified: pf_client.c:pf_client_post_connect,
  sendQueuedChannelData]. **So every drdynvc byte the client sends in answer to the
  module must be swallowed by the module**, or the back-end gets an unsolicited caps
  response or a stray Close.

## Why not FreeRDP's rdpgfx server channel

`rdpgfx_server_context_new(vcm)` with `Open()` is the obvious route (the shadow server uses
it). It does not fit the proxy:

1. `Open()` calls `WTSVirtualChannelOpenEx(..., WTS_CHANNEL_OPTION_DYNAMIC)`, which needs
   the WTS manager's drdynvc in `DRDYNVC_STATE_READY`
   [verified: channels/rdpgfx/server/rdpgfx_main.c:rdpgfx_server_open,
   libfreerdp/core/server.c:FreeRDP_WTSVirtualChannelOpenEx].
2. The manager sends the drdynvc caps request "once and only once", on its first
   `CheckFileDescriptor` with auto-open, and only if `drdynvc` is joined then
   [verified: server.c:WTSVirtualChannelManagerOpen]. The proxy calls it from the first
   loop iteration, before the MCS channel joins; the shadow server checks
   `WTSVirtualChannelManagerIsChannelJoined` first, the proxy does not
   [verified: pf_server.c:pf_server_handle_peer, shadow/shadow_client.c]. So in the
   proxy the manager most likely stays `INITIALIZED` without a drdynvc channel for the
   whole connection [inferred; check in the spike with
   `WTSVirtualChannelManagerGetDrdynvcState`]. The state is private
   (`libfreerdp/core/server.h`); the module cannot reset it.
3. DVC writes only queue to the manager; they go out in
   `WTSVirtualChannelManagerCheckFileDescriptor` [verified: server.c:wts_queue_send_item].
   Reads only arrive through `WTSReceiveChannelData`, which the proxy calls only while no
   client context exists [verified: pf_server.c:pf_server_receive_channel_data_hook]. In
   the wait it does.
4. The channel runs its own thread by default and the server sends ids from 1 up
   (`dvc_channel_id_seq`), the same ids the back-end will use
   [verified: rdpgfx_main.c:rdpgfx_server_open, server.c:FreeRDP_WTSVirtualChannelOpenEx].

All of this could be patched, but the module needs only a few PDUs. Writing them itself is
smaller and keeps the vendored patch series short.

## What the module would do during the wait

Only for a client that announced GFX and joined `drdynvc` (both logged per connection
today: `fastrdp_frontdiag.h`, `log_front_info`) [verified: fastrdp_plugin.c:log_front_info].
Everything below on the `drdynvc` static channel via `peer->SendChannelData`
[verified: include/freerdp/peer.h], read back through the `ReceiveChannelData` wrapper.

1. **drdynvc caps:** send `DYNVC_CAPS_VERSION` request, wait for the client's response
   (bounded, as `ws_reactivate` waits for Confirm Active). FreeRDP's own server asks for
   version 1 [verified: server.c:WTSVirtualChannelManagerOpen]. Version 1 is enough for
   the panel; what the back-end's later request does to it is the open question below.
2. **Create** `Microsoft::Windows::RDS::Graphics` with a channel id of the module's
   choosing, wait for the Create Response (status 0). Pick an id far from what back-ends
   use (they count from 1 [verified for FreeRDP servers: server.c; inferred for xrdp and
   Windows]).
3. **RDPGFX:** receive CapsAdvertise, answer CapsConfirm with one of the client's
   capability sets (8.0 is the plainest; for 10.x set the AVC-disabled flag)
   [inferred: MS-RDPEGFX]. Then ResetGraphics (desktop size, one monitor),
   CreateSurface (XRGB), MapSurfaceToOutput (0,0), and per frame StartFrame, SolidFill
   for the screen colour, WireToSurface1 for the panel rectangle, EndFrame.
4. **Codecs:** planar (codec id 0x000A) from the encoder the module already uses for
   32 bpp Bitmap Updates (`freerdp_bitmap_compress_planar` in `ws_add_tile`), or
   uncompressed (0x0000) for the first spike. FreeRDP's shadow server sends both this way
   [verified: shadow_client.c:shadow_client_send_planar, and its uncompressed path].
   Every RDPGFX PDU goes into a ZGFX segment wrapper; FreeRDP's
   `zgfx_compress_to_stream` is public and does not actually compress, it only wraps
   [verified: libfreerdp/codec/zgfx.c:zgfx_compress_segment].
5. **DVC framing:** split each message into DATA_FIRST and DATA PDUs of at most 1600
   bytes, as `FreeRDP_WTSVirtualChannelWrite` does [verified: server.c; the limit from
   MS-RDPEDYC, inferred]. Reassemble the client's chunks (static channel chunk flags) and
   DATA_FIRST/DATA before parsing.
6. **Frame acknowledge:** count them, log the first; no flow control is needed for one
   frame per second. CacheImportOffer: answer with an empty CacheImportReply
   [inferred: MS-RDPEGFX]. QoE acks: ignore.
7. **Input:** unchanged. Keys and mouse are fast-path, read by the same loop as the
   picker and the code field. The module must read the client for the whole wait
   (as `WaitingScreenObserve` does), so A8 needs patch 0007 like the picker.
8. **End of the wait:** DeleteSurface, then a drdynvc Close for the Graphics channel;
   wait (bounded, ~1 s) for the client's Close in return. FreeRDP clients send it
   [verified: channels/drdynvc/client/drdynvc_main.c:dvcman_channel_close]; mstsc unknown.
   Only then restore the proxy's `ReceiveChannelData` and return. A Close that arrives
   later would be queued for the back-end, where its id may mean a real channel.

## The hand-over

After the module returns, the back-end connects, the proxy sends the queued channel data,
then reactivates the front (Deactivate All, Demand Active)
[verified: pf_client.c:pf_client_post_connect, proxy_server_reactivate]. The back-end then
runs its own drdynvc start on the same static channel:

- **Second caps request in one connection.** The FreeRDP client answers every request and
  stays ready [verified: drdynvc_main.c:drdynvc_process_capability_request]. Whether
  MS-RDPEDYC allows it is not known from memory; mstsc unknown. If mstsc refuses, the
  module could drop the back-end's request (module filter `ClientChannelData` sees
  back-to-front pass-through data [verified: pf_channel.c:pf_channel_generic_back_data])
  and answer the back-end itself with the client's version. That breaks if the versions
  differ (version 3 adds compressed data PDUs) [inferred]; ask for the highest version in
  step 1 and answer the back-end with the lower of the two.
- **Second Graphics DVC.** The back-end creates `Microsoft::Windows::RDS::Graphics` again,
  probably with id 1. If the module's channel is closed and used another id, there is no
  collision [inferred]. A FreeRDP client tears down its surfaces on close and starts fresh
  on the next open [verified: channels/rdpgfx/client/rdpgfx_main.c:rdpgfx_on_close]. Its
  ZGFX history lives per plugin, not per channel [verified: rdpgfx_main.c, plugin init];
  harmless, because back-references are relative and the module's segments are
  uncompressed [inferred]. mstsc unknown.
- **Reactivation and DVCs.** As far as remembered, [MS-RDPBCGR] 1.3.1.3 keeps the MCS
  channels across a deactivation-reactivation, and [MS-RDPEDYC] ties DVCs to the drdynvc
  static channel, not to the activation, so a reactivation does not reset DVCs
  [inferred]. The FreeRDP client does not reset drdynvc on reactivation [inferred from
  the proxy's hand-over working with GFX today]. The A5 run 2 fits this: mstsc's GFX
  state survived a reactivation.
- **Back-end without GFX.** If the back-end then draws with legacy updates (GFX off at
  xrdp, the A10 case), mstsc sees a connection that used GFX and then went back to
  bitmaps. If the A5 hypothesis holds, that could be black [inferred]. All fastrdp
  back-ends use GFX by default (xrdp `gfx.toml`, gnome-remote-desktop probably requires
  it, unverified), so this matters mainly for lab set-ups with `GFX=false`; with
  `GFX=false` at the proxy the module must not use GFX at all.

## Alternative: the proxy intercepts drdynvc

`Intercept=drdynvc` (or the module's `StaticChannelToIntercept` filter) makes the proxy's
tracker sit on the channel. It does not help much: the tracker still passes the back-end's
caps request and the client's response, it would queue the client's answers to the
module for the back-end, and it knows nothing about a module-created channel
[verified: pf_channel_drdynvc.c:DynvcTrackerHandleCmd, DynvcTrackerPeekFn]. It only adds
that front data for unknown ids is dropped, which is a small safety net for a late Close.
A full fix there (the proxy answers drdynvc caps itself and renumbers DVC ids) is a
FreeRDP proxy patch of its own; not worth it unless mstsc refuses the second caps
request.

## Interaction with what exists

- `WaitingScreenReactivate` and `WaitingScreenObserve` stay lab switches; GFX mode
  implies reading the client for the whole wait.
- Refresh Rect and Suppress Output are legacy-path PDUs; in GFX mode the module would
  answer a Refresh Rect by sending the frame again [inferred: mstsc in GFX mode does not
  send them anyway].
- The panel code (`fastrdp_panel.h`), the countdown redraw and the picker's row redraws
  need only a second output path in `ws_send` / `ws_flush`: one GFX frame per redraw.
- Clients without GFX or without `drdynvc` keep the Bitmap Updates unchanged.

## Spike plan

Goal: answer the two mstsc questions with the least code. Lab switch, off by default:
proxy.ini `[FastRDP] WaitingScreenGfx=false` (role variable
`fastrdp_proxy_waiting_screen_gfx`), a warning per connection when on, ignored without
patch 0007 or without GFX/drdynvc in the client's announcement.

1. **Check the WTS state** (half an hour): log `WTSVirtualChannelManagerGetDrdynvcState`
   at the start of the wait, to confirm the manager is stuck and the module must speak
   drdynvc itself.
2. **Minimal writer** (1–1.5 days): drdynvc caps, Create, Close; RDPGFX CapsConfirm,
   ResetGraphics, CreateSurface, MapSurfaceToOutput, StartFrame, SolidFill,
   WireToSurface1 **uncompressed**, EndFrame, DeleteSurface. Reader: chunk and
   DATA_FIRST reassembly, CapsAdvertise, Create/Close responses, frame acks. Unit tests
   for the PDU bytes against FreeRDP's client parsers.
3. **Local, FreeRDP clients** (half a day): e2e proxy with the fake broker and a FreeRDP
   back-end, `xfreerdp3 /gfx` and `tests/proxy-e2e/client.c` with GFX loaded: the panel
   arrives over GFX (FreeRDP logs the caps and surface PDUs), the code field and the
   picker still read keys, the module's Close is answered, nothing reaches the back-end
   queue on `drdynvc`, and after the hand-over the back-end's caps request, Graphics
   create and frames work. Repeat with `GFX=false` at the proxy (module must stay on
   Bitmap Updates).
4. **Lab, mstsc** (one F19c-style run, Windows 11 and Windows 10): C1 fresh, session with
   GFX, X; C2 in the same process. Record with the TLS key log. Questions: (a) C2 shows
   the panel; (b) C1 and C2 reach the desktop after the hand-over, with event log
   1401/1402 for the back-end's GFX; (c) mstsc's answers to the second caps request and
   to the module's Close in the capture (the decoder in `tests/lab/rdpcapture/` names
   DVC creates; it would need the caps and close PDUs); (d) the same with an xrdp
   back-end, and once with a back-end without GFX, to see the risk above.
5. **Decide:** (a) and (b) yes: production work (planar, frame pacing, all redraw paths,
   tests, docs, switch on by default after a field test). (a) no: drop A8; the cause is
   not the output path. (b) no for the caps request: try the module-answers-caps variant
   once, else drop.

## Open points

- mstsc: everything about a second drdynvc caps exchange, a closed and re-created
  Graphics DVC in one connection, and legacy output after a closed GFX channel.
- The Windows App (macOS, iOS) and Remmina: same questions, lower priority.
- Whether MS-RDPEDYC and MS-RDPEGFX say anything explicit about repeated capability
  exchanges; worth a read of the current spec text before the spike.
