# MIT Kerberos SPNEGO fix (reference only)

`0001-Fix-SPNEGO-mechListMIC-parsing.patch` is upstream MIT krb5 commit
[942c5036](https://github.com/krb5/krb5/commit/942c5036e14066a1f4badfdf67716c47f2e33a39)
(ticket 9183), released in **krb5 1.22.2**. fastrdp does **not** build or ship krb5;
the `series` file is commented accordingly. Policy: [docs/vendoring.md](../../docs/vendoring.md).

**Problem.** Since 1.21, MIT's SPNEGO acceptor looks for the initiator's
`mechListMIC` under ASN.1 tag `0xA4` instead of `0xA3`. A MIC exchange is needed
whenever the acceptor selects a mechanism other than the initiator's first one, so
the initiator's last token is rejected with `GSS_S_DEFECTIVE_TOKEN`. FreeRDP 3 clients
offer Kerberos user-to-user first, so they trip over it against MIT-based RDP servers
(for example xrdp with NLA, PR #3868). Details: [docs/upstream.md §2](../../docs/upstream.md).

**Is it required for fastrdp?** **No.** No component in fastrdp's login paths uses an
MIT SPNEGO acceptor:
- freerdp-proxy accepts NLA with WinPR's own SPNEGO implementation and only uses
  MIT for the Kerberos mechanism itself;
- gnome-remote-desktop and KRdp also use WinPR;
- xrdp in fastrdp's setup receives one-time tokens, not NLA.

Building and shipping a private krb5 would also replace the library behind SSSD, PAM
and every other Kerberos user on the host, which is a much larger change than the fix.

**Why keep it here.** It documents the root cause found while testing xrdp's NLA pull
request, and it is the patch to point to in distribution bug reports. Affected
distribution packages: Debian 13 `1.21.3-5+deb13u1`, sid `1.22.1-3`, Ubuntu 26.04
`1.22.1-2ubuntu4.1`.

**Check a host.** `tests/krb5-spnego/run.sh` (`make check-krb5-spnego`): exit 0 means
the host's MIT acceptor is fine, exit 1 means it is affected.

**Drop it when** the distributions ship krb5 ≥ 1.22.2 or a backport of 942c5036.
