# fastrdp: Keycloak MFA flow without Ansible

fastrdp's web gateway asks Keycloak for `acr_values=mfa` and accepts only ID tokens with
`acr=mfa`. Keycloak issues that only when the realm has:

1. the WebAuthn **passwordless** policy for passkeys (user verification required,
   discoverable credential required, passkeys enabled, mediation `conditional`,
   attestation `none`, no AAGUID list) and the required action
   *Webauthn Register Passwordless* enabled;
2. the top-level flow **`fastrdp-mfa`** (no *Cookie* step):

   | Step | Requirement |
   |---|---|
   | Username Form | REQUIRED |
   | Password Form | REQUIRED |
   | sub-flow `fastrdp-mfa - 2FA unless passkey` (generic) | CONDITIONAL |
   | &nbsp;&nbsp;Condition - credential (config `fastrdp-mfa-conditional-credential`: Credentials = `webauthn-passwordless`, Included = off) | REQUIRED |
   | &nbsp;&nbsp;sub-flow `fastrdp-mfa - second factor` (generic) | REQUIRED |
   | &nbsp;&nbsp;&nbsp;&nbsp;OTP Form | ALTERNATIVE |
   | &nbsp;&nbsp;&nbsp;&nbsp;WebAuthn Authenticator | ALTERNATIVE |

3. client profile **`fastrdp-mfa-flow`** (executor `auth-flow-enforcer`: flow
   `fastrdp-mfa`, LoA 2) and client policy **`fastrdp-mfa`** (condition `acr-condition`:
   `mfa`, profile `fastrdp-mfa-flow`);
4. on the webgate's OIDC client: ACR-to-LoA map entry `mfa` → `2`.

`ansible/roles/web_gateway/files/fastrdp_keycloak_passkeys.py` (Ansible:
`fastrdp_web_passkeys: true`) creates exactly this. All methods below produce the same
result. Each was checked against Keycloak 26.8.1: afterwards that script, run with
`"check": true`, reported `{"changed": false, "changes": []}`.

Placeholders: `KEYCLOAK_HOST`, `REALM`, `CLIENT_ID` (the webgate's `clientId`),
`ADMIN_REALM`/`ADMIN_CLIENT_ID`/`ADMIN_CLIENT_SECRET` (a service account with
*realm-management* roles `manage-realm` + `manage-clients`) or an admin user.

## What does not work

- **Admin console *Partial import*** (Realm settings → Action → Partial import) does not
  import flows, authenticator configs, client profiles or client policies. In a test,
  `POST /partialImport` with them returned `added 0, skipped 0, overwritten 0`.
  *Partial export* does include the flows, but they cannot be imported back the same way.
- **No import for a single flow**: in the 26.8.1 admin console, the Authentication page
  has only *Create flow* and *Duplicate*. A flow has no import or JSON view.

## Method 1: fastrdp's own script, without Ansible (simplest)

Needs Python 3.11+ only (standard library), from the repo or the role's `files/`
directory:

```sh
echo '{"admin_url": "https://KEYCLOAK_HOST", "realm": "REALM", "client_id": "CLIENT_ID",
       "admin_realm": "ADMIN_REALM", "admin_client_id": "ADMIN_CLIENT_ID",
       "admin_client_secret": "ADMIN_CLIENT_SECRET", "check": true}' |
  python3 ansible/roles/web_gateway/files/fastrdp_keycloak_passkeys.py
```

With an admin user, use `"admin_user": "...", "admin_password": "..."` (realm `master`,
client `admin-cli` are the defaults). `"check": true` lists the changes. Remove it to
apply them. Run the script again to verify: it should print `"changed": false`.

## Method 2: `fastrdp-mfa-kcadm.sh` (Keycloak admin CLI; tested)

Needs `kcadm.sh` (in `bin/` of any Keycloak 26.x distribution; Java 17+), `jq` and bash.

```sh
export PATH=/opt/keycloak/bin:$PATH          # wherever kcadm.sh is
# service account (preferred):
kcadm.sh config credentials --server https://KEYCLOAK_HOST --realm ADMIN_REALM \
    --client ADMIN_CLIENT_ID --secret 'ADMIN_CLIENT_SECRET'
# or an admin user (prompts for the password):
kcadm.sh config credentials --server https://KEYCLOAK_HOST --realm master --user ADMIN_USER

./fastrdp-mfa-kcadm.sh -r REALM -c CLIENT_ID --check   # lists "would change: ..."
./fastrdp-mfa-kcadm.sh -r REALM -c CLIENT_ID           # applies
./fastrdp-mfa-kcadm.sh -r REALM -c CLIENT_ID           # "no changes: ... already configured"
```

How it works:
- It reads the current client profiles and policies, merges its own entry by name and
  writes the whole list back, because Keycloak's PUT replaces the lists. Other profiles
  and policies are kept.
- It adds `mfa: 2` to the client's `acr.loa.map` and keeps any other entries.
- When it updates the realm, it sends all `webAuthnPolicyPasswordless*` fields, with its
  own values changed. Keycloak rebuilds the whole policy from such a request.
- It skips every piece that is already correct. If a flow `fastrdp-mfa` exists with a
  different structure, the script prints the current and wanted steps and stops.
  `--rebuild` deletes the flow's steps and builds them again, which is what the Ansible
  script does. A built-in flow of that name is always refused.
- Options: `--flow`, `--acr`, `--loa`, `--profile`, `--policy`, `--second-factors`
  (comma list, e.g. add a privacyIDEA authenticator id) and `--mediation`. Hardware-only
  AAGUID lists are not supported; use Method 1 for those.
- `KCADM_CONFIG` selects a different kcadm session file. Use `KCADM_OPTS` for extra
  options, e.g. `--truststore`. A run takes about 40 s, because each kcadm call starts
  a JVM.

The descriptions of the profile and policy say "managed by Ansible". They are identical
on purpose: this way the Ansible role and this script recognise each other's result
as already configured.

## Method 3: admin console by hand, plus the JSON editor for client policies

1. **Authentication → Policies → Webauthn Passwordless Policy**: set *User verification
   requirement* = Required, *Discoverable credential* = Required, *Enable Passkeys* = on,
   *Passkey Mediation* = Conditional, *Attestation conveyance preference* = None,
   *Acceptable AAGUIDs* empty → Save.
2. **Authentication → Required actions**: *Webauthn Register Passwordless* enabled
   (it is enabled by default).
3. **Authentication → Create flow**: name `fastrdp-mfa`, type *Basic flow*. Then:
   - *Add step* → Username Form → REQUIRED; *Add step* → Password Form → REQUIRED;
   - *Add sub-flow* `fastrdp-mfa - 2FA unless passkey` (Generic) → CONDITIONAL;
   - in that sub-flow: *Add condition* → *Condition - credential* → REQUIRED. Use its
     gear icon to configure it: alias `fastrdp-mfa-conditional-credential`, Credentials =
     `webauthn-passwordless`, Included = off;
   - in that sub-flow: *Add sub-flow* `fastrdp-mfa - second factor` (Generic) → REQUIRED;
   - in `fastrdp-mfa - second factor`: *Add step* OTP Form → ALTERNATIVE, *Add step*
     WebAuthn Authenticator → ALTERNATIVE.

   Do not add *Cookie*, and do not bind the flow as the browser flow. The client policy
   enforces it.
4. **Realm settings → Client policies → Profiles → JSON editor**. The editor shows ONE
   JSON array: the built-in profiles (`"global": true`) and the realm's own profiles
   (`"global": false`). *Save* writes back all entries without `"global": true` as the
   realm's complete profile list. To merge, keep everything that is there, add a comma
   after the last `}` and paste the object from `profiles[0]` of
   `fastrdp-mfa-client-policies.json` before the closing `]`. Then *Save*.
   (Deleting an entry from the array deletes that profile.)
5. **Client policies → Policies → JSON editor**: do the same with `policies[0]`. Add the
   profile first, because the policy refers to it.
6. **Clients → CLIENT_ID → Advanced → Advanced settings → ACR to LoA Mapping**: add key
   `mfa`, value `2` → Save.

The admin UI code of 26.8.1 was checked for steps 4–5, and the exact REST request that
its *Save* sends was replayed: the other profile and policy were kept, and the script
check showed no client-policy changes. The browser itself was not clicked through.
Steps 1–3 and 6 were not done in a browser either. They produce the same objects that
Method 2 creates through the same REST API.

## Method 4: keycloak-config-cli (adorsys; tested, with caveats)

`fastrdp-mfa-flow.keycloak-config-cli.yaml`. The newest release, v6.5.1 (2026-05-22),
is built against Keycloak **26.5.5** at most. There is no build for 26.8, and the project
supports "the latest 4 releases". The 26.5.5 jar worked against 26.8.1, with these
caveats (all observed):

- It rejects the 26.6+ realm fields `webAuthnPolicyPasswordlessResidentKey` and
  `...Mediation` (`Unrecognized field`). The YAML leaves them out. Afterwards, set them
  with `kcadm.sh update realms/REALM -s webAuthnPolicyPasswordlessResidentKey=required -s webAuthnPolicyPasswordlessMediation=conditional`,
  or in the admin console.
- Keycloak ignores the passwordless fields unless `webAuthnPolicyPasswordlessRpEntityName`
  is in the request. The YAML therefore sets it; keep it at your realm's value (default
  `keycloak`). Passwordless fields that are not in the file are reset to their defaults.
- `clientProfiles`/`clientPolicies` **replace** the realm's lists. In the test, an
  existing unrelated profile was deleted. Copy your existing profiles and policies into
  the file.
- The client's `acr.loa.map` is **set**, not merged (`{"other":5}` became `{"mfa":2}`).
  The other client fields were kept.
- Runs are skipped while the file's checksum is unchanged. Use
  `--import.cache.enabled=false` to force a run.

```sh
KC_REALM=REALM FASTRDP_CLIENT_ID=CLIENT_ID java -jar keycloak-config-cli-26.5.5.jar \
  --keycloak.url=https://KEYCLOAK_HOST --keycloak.login-realm=ADMIN_REALM \
  --keycloak.grant-type=client_credentials --keycloak.client-id=ADMIN_CLIENT_ID \
  --keycloak.client-secret='ADMIN_CLIENT_SECRET' \
  --import.var-substitution.enabled=true \
  --import.files.locations=fastrdp-mfa-flow.keycloak-config-cli.yaml
```

(Release jar: github.com/adorsys/keycloak-config-cli/releases/tag/v6.5.1, sha256
`df6939a1d9c40d5ab7e1fb690082ea8980dbbf402ca92a9968b90b652cb3ca9a`.) Choose this method
only if you already manage the realm with keycloak-config-cli.

## Method 5: new realm only, full realm JSON

`fastrdp-mfa-new-realm.json` is a complete realm representation: the passwordless
policy, the three flows, the authenticator config, client profile and policy, and the
client `fastrdp-web` from `docs/examples/keycloak-fastrdp-web-client.json`, with
`acr.loa.map` `{"mfa":2}`. Before importing, replace `YOUR_REALM` and the host
`rdp1.lab.example.com`. It works only when the realm is **created**:
- admin console: *Create realm* → *Resource file* (tested through the same REST
  call, `POST /admin/realms`: script check reported no changes, and the built-in flows
  and the default required actions were all present);
- `kc.sh import --file fastrdp-mfa-new-realm.json` with the server stopped (not
  tested).

Do **not** add a `requiredActions` list to this file: in a test, the new realm then had
only the listed actions, plus `delete_account`.

## Verify

1. `fastrdp_keycloak_passkeys.py` with `"check": true` (Method 1) prints
   `{"changed": false, "changes": [], "check": true}`. With Method 2,
   `./fastrdp-mfa-kcadm.sh -r REALM -c CLIENT_ID --check` prints `no changes: ...`.
2. Open `https://<webgate>/web/` in a private window. Keycloak shows the
   **username-only** form with **"Sign in with Passkey"** (the passkey autofill), and
   no password field. Signing in with a passkey skips the password; password + OTP (or a
   security key) also works. Password alone stops at the OTP step.
3. `journalctl -u fastrdp-webgate` shows `web login <user>`. If it instead says
   `acr '1' does not prove MFA`, the flow or policy is missing, or the user has no
   second factor (docs/web-access.md, "Symptom: acr '1' does not prove MFA").

## Files

- `fastrdp-mfa-kcadm.sh` – Method 2 (tested)
- `fastrdp-mfa-client-policies.json` – profile + policy objects for the JSON editor (Method 3)
- `fastrdp-mfa-flow.keycloak-config-cli.yaml` – Method 4 (tested with the caveats above)
- `fastrdp-mfa-new-realm.json` – Method 5 (new realms only; tested via `POST /admin/realms`)
