# Blog post draft: introducing fastrdp

Draft for blog.linux-ng.de. **Not published yet.** The post exists in WordPress as a **draft, post 2493**
(preview: `https://blog.linux-ng.de/?p=2493&preview=true`), with the six diagrams (media 2487–2492) and four
screenshots (media 2500, 2501, 2534, 2535) uploaded. Updated on 2026-10-23 for release 0.7.1; the WordPress draft is the
master copy of the wording, and the files here mirror it.

| File | What it is |
|---|---|
| `fastrdp-blog-post.md` | The post in Markdown, with front matter (title, excerpt, categories, tags, featured image), figure references, captions and alt texts |
| `fastrdp-blog-post.html` | The same content as block-editor (Gutenberg) markup, identical to the WordPress draft's content (real media URLs and attachment ids) |
| `diagrams/*.drawio` | Six diagrams as uncompressed mxGraph XML (diff-able, editable in diagrams.net / draw.io desktop) |
| `diagrams/*.svg`, `diagrams/*.png` | Exports of the six diagrams. PNGs are 2× (about 2700 px wide) for sharp display at about 1350 px |
| `../images/mfa/*.png` | Screenshots of the waiting screen (rendered with the real `fastrdp_panel.h` and broker texts) and of the webgate pages (real handlers, headless Chromium), example data only (alice, rdp.example.org, 192.0.2.x). The post uses `waiting-push-or-web`, `web-approve`, `web-approve-warning` and `waiting-picker`; the docs use the others too |

Figures in the post: 1–4 and 9–10 are the diagrams; 5–8 are the screenshots in the section
"The second factor, from the user's side".

Diagrams:

1. `01-approaches-compared`: xrdp alone vs native per-desktop servers vs ogon-style broker vs fastrdp hybrid
2. `02-architecture-overview`: clients → proxy + module (waiting screen) → broker → loopback back-ends, with KDC, privacyIDEA, Keycloak, the web gateway's approval page and notifications (ntfy / Web Push)
3. `03-login-sequence`: Kerberos NLA → broker login → second factor by mode (KDC evidence, or waiting screen + privacyIDEA push / web approval with QR code, Keycloak passkey sign-in, optional notification) → optional desktop picker → token / back-end start → session
4. `04-gpu-encoding-paths`: rendering and H.264 encoder per back-end, with fallbacks
5. `05-build-delivery-pipeline`: sources.yml + patches → build scripts → Ansible / packages / CI → APT repository + corresponding source
6. `06-web-path`: browser → nginx → webgate ↔ Keycloak → broker web token → Guacamole → guacd → proxy; plus `/web/approve`, `/web/notify` (→ ntfy / Web Push), the stored desktop for RDP logins and the `.rdp` download

Colours, the same in every diagram: blue = front end (proxy, web gateway); orange = broker; green = back-ends and sessions; purple = identity/MFA (KDC, privacyIDEA, Keycloak); grey = clients, external parties and inputs. In diagrams 1 and 4, green, yellow and red mean covered, partly covered/fallback and not covered.

## Publishing

Steps 1–8 below were done in October 2026 (post 2493, draft). What is left: re-check the claims below,
preview (table, code block and the two phone screenshots at 360 px on mobile), then publish. For later
content changes, edit the draft in WordPress and mirror the changes here (or the other way round), so the
two stay identical.

Original steps, for reference:

1. **Upload the media.** Upload the six `diagrams/*.png` files (Media → Add New). Use PNG: WordPress blocks SVG uploads unless a plugin allows them, and the SVGs use `foreignObject` for HTML labels. Set each image's alt text from the `![...]` text in the Markdown file.
2. **Fix the image URLs.** In `fastrdp-blog-post.html`, replace `https://blog.linux-ng.de/wp-content/uploads/REPLACE-AFTER-UPLOAD/` with the real upload path, for example `…/wp-content/uploads/2026/10/`. Check the file names, because WordPress may append `-1` and similar suffixes. Optionally add `"id":<attachment id>` to each `<!-- wp:image {...} -->` comment so the editor links the block to the media item. Without it the block still works, as an external-URL image.
3. **Create the post.** Posts → Add New. Paste the title from the front matter into the title field. Open the code editor (Ctrl+Shift+Alt+M, or ⋮ → Code editor), paste the whole HTML file and switch back to the visual editor. Every block should show without "invalid content" warnings. If one does, use "Attempt block recovery".
4. **Excerpt** (156 characters): *One RDP front end with Kerberos SSO and MFA, a small broker, and the best native back-end for every Linux desktop, X11 and Wayland. Why fastrdp is a hybrid.*
5. **Categories.** These already exist on the site: Remote Desktop, Linux, Kerberos, SSO, GPU. Optionally add Ubuntu and Debian.
6. **Tags.**
   - Already exist: RDP, ogon, Kerberos, MFA, privacyIDEA, Keycloak, Yubikey, Smartcard, PKCS#11, ffmpeg, Debian Packaging, APT, GitHub Actions, GPL, draw.io.
   - New, if wanted: FreeRDP, xrdp, Wayland, GNOME, KDE Plasma, H.264, VA-API, NVENC.
7. **Featured image.** Use `02-architecture-overview.png`, or a crop of its upper half (clients → proxy → broker) if the theme uses wide, short header images.
8. **Optional: an older post.** The site already has one post tagged *ogon* and *RDP* in category *Remote Desktop*. Consider linking it from the ogon paragraph.
9. Save as **draft** and preview. Check that the table and the code block are readable on mobile.

Editing the diagrams: open the `.drawio` file in diagrams.net (File → Open from → Device) or draw.io desktop. To re-export, use File → Export as → PNG (zoom 200 %, border 20) or SVG. With draw.io desktop installed, you can also run `drawio --export --format png --scale 2 --border 20 <file>.drawio`. The exports here were made with the official draw.io viewer (`viewer.diagrams.net/js/viewer-static.min.js`) in headless Chromium. They are the viewer's own `getSvg()` output, rasterised at 2×.

## Claims to check before publishing

The post was first written from commit fe9743c and updated on 2026-10-23 from v0.7.1 (commit cf269c8).
Check the following once more, because they are time-sensitive, phrased from my reading, or not yet
validated.

**Resolved since the first draft:**
- [x] APT repository live: `https://linuxrrze.github.io/fast-rdp-server/` answers 200, suites
  `resolute-stable`/`-testing` and `trixie-stable`/`-testing`, signed `InRelease`, stable has 0.7.1
  and fastrdp-freerdp3 3.32.2-6 (checked 2026-10-23). The post now says CI *publishes* it.
- [x] Windows mstsc with Kerberos: confirmed by a field report (2026-10-22, two Windows clients, AD-joined
  host, user-to-user; backlog K10, windows-clients.md §3.14). Moved to "Confirmed in the field".
- [x] Broker test count updated: 521 (`make test-broker` on v0.7.1). The README status table still says
  127; update it there too.

**Status and validation (must stay hedged):**
- [ ] GPU encoding (VA-API, NVENC, QSV) is **not yet tested on real Intel, AMD or NVIDIA hardware**, for all back-ends.
- [ ] The GNOME and Plasma headless back-ends have **not run on a lab host**; headless KRdp is unofficial.
  Full xrdp sessions through the proxy still need a lab run. (The mstsc field report says "login
  succeeded" but does not say which desktop; if it was a full xrdp session, this hedge can shrink.)
- [ ] Waiting screen, QR code and desktop picker are tested with FreeRDP clients only; **mstsc / Windows App
  still to confirm** (lab S3/L15). The post says the first test with a real Windows client showed a black
  window without the screen (commit 5e898ac).
- [ ] Web approval with a real Keycloak **and** mstsc together: untested in the lab (windows-clients.md
  MFA table). Keycloak's passkey flow itself is tested against Keycloak 26.8.1 (`make test-keycloak`,
  manual, not in CI).
- [ ] Notifications: not tested on real iOS/Android devices (backlog W1).
- [ ] KDC evidence as MFA (K11): implemented; PAC SIDs with a real AD and WHfB/smartcard SIDs unconfirmed.
- [ ] Audio/microphone (A1): implemented, not tested with real clients.
- [ ] Power-action polkit rule (H1): implemented, host validation pending (the post states the behaviour,
  not that it is validated).
- [ ] Smartcard logon tested only with a software token (SoftHSM).
- [ ] Setup assistant/preflight: the README status table says "not yet run against a real target"; field
  reports (commit 2d8e2e7) suggest it has been used. The post now says "in a systematic lab run"; decide
  which wording fits.
- [ ] "First deployments on real hosts also turned up a few Ansible problems, fixed in 0.6.1 and 0.7.0":
  from the commit messages of 42bc3f2/102830b (deploy failures on a host with the web gateway). OK to
  mention publicly?

**Numbers:**
- [ ] Proxy overhead table and "0.3–0.5 % of one core per Mbit/s" (docs/performance.md, FreeRDP 3.32.1,
  RFX, Ryzen 7 7735HS). Latency "below the noise (about ±10 ms)".
- [ ] "521 tests" for the broker (re-run `make test-broker` if more commits land before publishing).
- [ ] xrdp encoder test: 30/30 frames, luma PSNR 56 dB at QP 20 (patches/xrdp/README.md).
- [ ] "About one core or more per active 1080p session" for x264 (the repo's estimate, not a measurement).
- [ ] "19 CVE fixes in 0.10.5–0.10.6.1" (patches/xrdp/README.md).
- [ ] "Seven fastrdp patches" on FreeRDP 3.32.2 (patches/freerdp/0001–0007).
- [ ] "Release 0.7.1 (October 2026)": tag v0.7.1 is dated 2026-10-22 22:53 +0200; the post gives only the month.

**Versions and third-party facts (as of 2026-10-23):**
- [ ] Debian 13 and Ubuntu 26.04 ship xrdp 0.10.1; Debian 13 ships FreeRDP 3.15.0; Ubuntu 26.04 ships
  FreeRDP 3.32.1 without H.264.
- [ ] xrdp PR #3868 (NLA) is still open and unmerged.
- [ ] MIT krb5 regression: 1.21.0–1.22.1, commit fdceb225, fixed in 1.22.2 (942c5036, ticket 9183);
  Debian 13 and Ubuntu 26.04 still affected.
- [ ] FreeRDP slot id and U2U acceptor bugs still present upstream; "nothing has been submitted yet"
  (docs/upstream.md policy). Update if reports or PRs went out.
- [ ] ogon "dormant since about 2019".
- [ ] GNOME 50 and Plasma 6.8 Wayland-only (Ubuntu 26.04's Plasma 6.6 still has X11, hence `plasma-x11`).
- [ ] Web Push on iPhone/iPad only as a home-screen web app (iOS 16.4+); ntfy works on Android without
  Google services (notifications.md).

**Interpretations I added (not stated in these words in the repo):**
- [ ] Approach (a): "MFA only through PAM at xrdp's login dialog".
- [ ] Approach (b): "no common place for MFA" and "separate configuration" for g-r-d and KRdp on their own.
- [ ] Approach (c): ogon's coverage marked "not evaluated" in figure 1.
- [ ] "It's a bit like number matching in push apps, except that you compare instead of type" (the repo
  calls it a correlation code).
- [ ] "mstsc always starts Kerberos under CredSSP with a user-to-user request" (windows-clients.md §3.14:
  first token KERB-TGT-REQUEST, seen in the field report).

**Links and infrastructure:**
- [ ] GitHub repository, quick start link (`blob/main/docs/quickstart.md`) and the APT repository resolve.
- [ ] privacyIDEA push needs a push token and, for Kerberos SSO, the service account with
  `triggerchallenge`; web approval needs the web gateway and Keycloak with an MFA flow (`acr=mfa`).
