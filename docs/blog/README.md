# Blog post draft: introducing fastrdp

Draft for blog.linux-ng.de. **Nothing has been published.** No WordPress post or media exists yet.

| File | What it is |
|---|---|
| `fastrdp-blog-post.md` | The post in Markdown, with front matter (title, excerpt, categories, tags, featured image), figure references, captions and alt texts |
| `fastrdp-blog-post.html` | The same content as block-editor (Gutenberg) markup, ready for the code editor. Image URLs are placeholders |
| `diagrams/*.drawio` | Six diagrams as uncompressed mxGraph XML (diff-able, editable in diagrams.net / draw.io desktop) |
| `diagrams/*.svg`, `diagrams/*.png` | Exports of the six diagrams. PNGs are 2× (about 2700 px wide) for sharp display at about 1350 px |

Diagrams:

1. `01-approaches-compared`: xrdp alone vs native per-desktop servers vs ogon-style broker vs fastrdp hybrid
2. `02-architecture-overview`: clients → proxy + module → broker → loopback back-ends, with KDC, privacyIDEA and Keycloak
3. `03-login-sequence`: Kerberos NLA → MFA push → desktop choice → token / back-end start → session
4. `04-gpu-encoding-paths`: rendering and H.264 encoder per back-end, with fallbacks
5. `05-build-delivery-pipeline`: sources.yml + patches → build scripts → Ansible / packages / CI → APT repository + corresponding source
6. `06-web-path`: browser → nginx → webgate ↔ Keycloak → broker web token → Guacamole → guacd → proxy

Colours, the same in every diagram: blue = front end (proxy, web gateway); orange = broker; green = back-ends and sessions; purple = identity/MFA (KDC, privacyIDEA, Keycloak); grey = clients, external parties and inputs. In diagrams 1 and 4, green, yellow and red mean covered, partly covered/fallback and not covered.

## Publishing

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

Every statement comes from the repository at commit fe9743c. Check the following once more, because they are time-sensitive, phrased from my reading, or not yet validated:

**Status and validation (must stay hedged):**
- [ ] GPU encoding (VA-API, NVENC, QSV) is **not yet tested on real Intel, AMD or NVIDIA hardware**. This applies to all back-ends, including the xrdp patch.
- [ ] The GNOME and Plasma headless back-ends have **not run on a lab host**. Headless KRdp with `kwin_wayland --virtual` is unofficial.
- [ ] Full xrdp sessions through the proxy still need a lab run.
- [ ] **Windows mstsc with Kerberos** against fastrdp is not tested yet. Smartcard logon has been tested only with a software token (SoftHSM), not with real cards or an AD PKI.
- [ ] The **setup assistant and preflight** have not been run against a real target.
- [ ] Containers and Keycloak on the web path still need a lab run.

**Numbers:**
- [ ] Proxy overhead table and "0.3–0.5 % of one core per Mbit/s" (docs/performance.md, FreeRDP 3.32.1, RFX, Ryzen 7 7735HS). Latency "below the noise (about ±10 ms)".
- [ ] "127 unit/protocol tests" for the broker (README status table). Update this if the count changes before publishing.
- [ ] xrdp encoder test: 30/30 frames, luma PSNR 56 dB at QP 20 (patches/xrdp/README.md).
- [ ] "About one core or more per active 1080p session" for x264 (docs/vendoring.md, patches/xrdp/README.md). This is the repo's estimate, not a measurement.
- [ ] "19 CVE fixes in 0.10.5–0.10.6.1" (patches/xrdp/README.md).

**Versions and third-party facts (as of 2026-10-19):**
- [ ] Distribution versions: Debian 13 and Ubuntu 26.04 ship xrdp 0.10.1; Debian 13 ships FreeRDP 3.15.0; Ubuntu 26.04 ships FreeRDP 3.32.1 without H.264.
- [ ] xrdp PR #3868 (NLA) is still open and unmerged.
- [ ] MIT krb5 regression: versions 1.21.0–1.22.1, commit fdceb225, fixed in 1.22.2 (942c5036, ticket 9183). Debian 13 and Ubuntu 26.04 are still affected.
- [ ] FreeRDP slot id bug is still present upstream. The post says "nothing has been submitted yet"; update this if reports or PRs went out in the meantime.
- [ ] ogon is "dormant since about 2019" (docs/plan.md uses "~2019").
- [ ] GNOME 50 and Plasma 6.8 are described as Wayland-only. Note that Ubuntu 26.04's Plasma 6.6 still ships an X11 session, which is why `plasma-x11` exists.

**Interpretations I added (not stated in these words in the repo):**
- [ ] Approach (a): "MFA only through PAM at xrdp's login dialog". This is derived from the plan's PAM fallback (pam_sss + privacyIDEA PAM).
- [ ] Approach (b): "no common place for MFA" and "separate configuration" for g-r-d and KRdp used on their own. The repo doesn't evaluate the MFA options of the native servers. KRdp's NLA/Kerberos support on its own is not stated in the repo, so the matrix only credits g-r-d.
- [ ] Approach (c): ogon's coverage of X11, Wayland, NLA, MFA and GPU is marked "– not evaluated". The repo only says that it is dormant and that its broker model is the inspiration.

**Links and infrastructure:**
- [ ] The **APT repository is not live yet**: `https://linuxrrze.github.io/fast-rdp-server/` returned 404 on 2026-10-19. The post says CI "is set up to publish" a signed APT repository. Either make sure the first publish has run before publishing the post, or keep this wording.
- [ ] The GitHub repository and the quick start link (`blob/main/docs/quickstart.md`) resolve publicly, and `main` contains commit fe9743c or later.
- [ ] The post mentions privacyIDEA push "until it is confirmed". This needs a privacyIDEA push token and, for Kerberos SSO, the service account with `triggerchallenge` (docs/auth-matrix.md). It's fine for a blog post, but don't promise push without that setup.
