# Developer checks. Integration tests need FreeRDP 3.32+ dev files; see tests/proxy-e2e/.
.PHONY: deb test-xrdp-encoder test-wlroots test test-broker test-webgate test-pam test-gpu test-e2e test-e2e-nla test-e2e-smartcard check-krb5-spnego perf-tools perf-proxy lint

test: test-broker test-webgate test-pam test-gpu lint

test-broker:
	cd broker/brokerd && python3 -m unittest discover -s tests

test-webgate:   # needs python3-cryptography
	cd broker/webgate && python3 -m unittest discover -s tests

test-pam:
	$(MAKE) -C broker/pam_fastrdp_token check

test-gpu:
	cd tests/gpu && python3 -m unittest test_session_report

perf-tools:
	$(MAKE) -C tests/perf/rdpbench

perf-proxy:
	tests/perf/proxy-overhead.sh 15 3

test-xrdp-encoder:   # XRDP_SRC=<patched, built xrdp tree>; libavcodec-dev
	patches/xrdp/test/run_test.sh $(XRDP_SRC) libx264
	FALLBACK= patches/xrdp/test/run_test.sh $(XRDP_SRC) h264_vaapi null

test-wlroots:   # xvfb xwayland wlr-randr wl-clipboard xclip x11-utils + sway/labwc/wayfire
	tests/wlroots/run.sh

test-e2e:
	tests/proxy-e2e/run.sh

test-e2e-nla:
	tests/proxy-e2e/run_nla.sh

test-e2e-smartcard:   # + krb5-pkinit softhsm2 opensc p11-kit-modules
	tests/proxy-e2e/run_smartcard.sh

check-krb5-spnego:   # libwinpr3-dev libkrb5-dev krb5-kdc krb5-admin-server; exit 1 = affected
	tests/krb5-spnego/run.sh

lint:
	cd ansible && ansible-lint site.yml
	shellcheck -x broker/session/libexec/startwm.sh broker/session/libexec/session-plasma \
		broker/session/libexec/kwin-wayland-launch broker/session/libexec/wlroots-in-x \
		tests/proxy-e2e/*.sh tests/krb5-spnego/run.sh tests/smoke/*.sh tests/perf/*.sh patches/xrdp/test/run_test.sh \
		third_party/*.sh
	shellcheck -e SC1090,SC2015 tests/wlroots/run.sh
	shellcheck packaging/ci/*.sh packaging/apt/*.sh debian/bin/*
	packaging/ci/check-build-deps.sh

deb:   # Debian/Ubuntu packages into ..; build deps: apt-get build-dep ./ (docs/packaging.md)
	dpkg-buildpackage -us -uc -b
