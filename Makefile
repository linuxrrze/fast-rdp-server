# Developer checks. Integration tests need FreeRDP 3.32+ dev files; see tests/proxy-e2e/.
# Overview of every test, what it guards and where CI runs it: tests/README.md.
.PHONY: deb test-xrdp-encoder test-wlroots test test-all test-broker test-webgate test-pam test-gpu \
	test-scripts test-publish test-ansible test-proxy-module test-e2e test-e2e-nla test-e2e-smartcard \
	test-e2e-smartcard-softhsm check-krb5-spnego perf-tools perf-proxy lint lint-ci test-docs \
	test-keycloak test-prototypes test-lab

test: test-broker test-webgate test-pam test-proxy-module test-gpu test-prototypes test-lab lint

# Everything that runs locally without root (missing tools: SKIP, or FAIL with
# FASTRDP_TESTS_STRICT=1). Needs libpam0g-dev, libcjson-dev, python3-cryptography, ansible-core,
# ansible-lint, shellcheck, dpkg-dev, curl, reprepro, gnupg, apt, nodejs (polkit rule test).
test-all: test test-scripts test-publish test-ansible

test-broker:
	cd broker/brokerd && python3 -m unittest discover -s tests

# run_if NAME, CHECK, MISSING, COMMAND: COMMAND if CHECK succeeds; otherwise SKIP, or FAIL with
# FASTRDP_TESTS_STRICT=1 (as in CI), like need() in tests/lib.sh
run_if = if ( $(2) ) >/dev/null 2>&1; then $(4); \
	elif [ "$${FASTRDP_TESTS_STRICT:-0}" = 1 ]; then echo "FAIL $(1): missing $(strip $(3))"; exit 1; \
	else echo "SKIP $(1): missing $(strip $(3))"; fi
comma := ,
# with_tool NAME, TOOL, COMMAND: COMMAND if TOOL is installed (run_if on command -v)
with_tool = $(call run_if,$(1),command -v $(2),$(2),$(3))

test-webgate:   # needs python3-cryptography
	@$(call run_if,test-webgate,python3 -c 'import cryptography',python3-cryptography,\
	  cd broker/webgate && python3 -m unittest discover -s tests)

test-pam:       # needs libpam0g-dev, libcjson-dev, pkg-config
	@$(call run_if,test-pam,pkg-config --exists libcjson && echo '#include <security/pam_appl.h>' | $(CC) -E -x c -,\
	  libpam0g-dev libcjson-dev pkg-config,$(MAKE) -C broker/pam_fastrdp_token check)

# AllowTlsFrom address lists (fastrdp_addr.h), CredSSP mechanism offers (fastrdp_spnego.h),
# PAC group SIDs (fastrdp_pac.h), the waiting screen's panel (fastrdp_panel.h) and its code
# field (fastrdp_code.h) and InputTrace's event classes (fastrdp_inputtrace.h) of the proxy
# module; gcc only, no FreeRDP
test-proxy-module:
	@$(call with_tool,test-proxy-module,$(CC),mkdir -p build && \
	  $(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -o build/test_addr tests/proxy-module/test_addr.c && \
	  build/test_addr && \
	  $(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -o build/test_spnego tests/proxy-module/test_spnego.c && \
	  build/test_spnego && \
	  $(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -o build/test_pac tests/proxy-module/test_pac.c && \
	  build/test_pac && \
	  $(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -o build/test_panel tests/proxy-module/test_panel.c && \
	  build/test_panel && \
	  $(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -o build/test_code tests/proxy-module/test_code.c && \
	  build/test_code && \
	  $(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -o build/test_inputtrace tests/proxy-module/test_inputtrace.c && \
	  build/test_inputtrace && \
	  $(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -o build/test_keylog tests/proxy-module/test_keylog.c && \
	  build/test_keylog && \
	  $(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -o build/test_frontdiag tests/proxy-module/test_frontdiag.c && \
	  build/test_frontdiag && \
	  $(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -o build/test_gfx tests/proxy-module/test_gfx.c && \
	  build/test_gfx && \
	  $(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -o build/test_redirect tests/proxy-module/test_redirect.c && \
	  build/test_redirect)

test-gpu:
	cd tests/gpu && python3 -m unittest test_session_report

test-scripts:   # fetch.sh, build-key.sh, build-xrdp.sh site config, packaging/ci/*.sh, TERMSRV helpers, base role's package check; dpkg-dev curl patch xz-utils git
	tests/packaging/test_fetch.sh
	tests/packaging/test_build_key.sh
	tests/packaging/test_ci_scripts.sh
	tests/packaging/test_publish_gh_pages.sh
	tests/packaging/test_check_pages_live.sh
	tests/ansible/test_outdated_packages.sh
	tests/packaging/test_xrdp_site_config.sh
	python3 -m unittest -v tests/identity/test_termsrv_helpers.py

test-publish:   # packaging/apt/publish.sh + apt-get update; reprepro gnupg dpkg-dev apt
	tests/packaging/test_publish.sh

test-ansible:   # ansible-core, nodejs; syntax check + role templates rendered and parsed; Keycloak script + sample client (offline)
	@$(call with_tool,test-ansible,ansible-playbook,cd ansible && ansible-playbook --syntax-check site.yml)
	python3 -m unittest -v tests/ansible/test_roles_static.py
	python3 -m unittest -v tests/ansible/test_templates.py
	python3 -m unittest -v tests/keycloak/test_keycloak_passkeys.py
	python3 -m unittest -v tests/keycloak/test_keycloak_examples.py

# FreeRDP switches in docs/freerdp-client.md, docs/client-guide.md and docs/manual-setup.md
# vs. FreeRDP's own switch table. Downloads the vendored FreeRDP source (network, or FASTRDP_SOURCES_CACHE);
# FREERDP_SRC=<tree> or FREERDP_HELP_CMD=xfreerdp3 instead. Not in test-all (network).
# Also: fastrdp_plugin.c:N line references in the docs point into the function they name
# (offline).
test-docs:   # python3; curl patch for the download
	python3 -I tests/docs/check_module_refs.py --self-test
	tests/docs/test_freerdp_switches.sh

perf-tools:
	$(MAKE) -C tests/perf/rdpbench

perf-proxy:
	tests/perf/proxy-overhead.sh 15 3

test-xrdp-encoder:   # XRDP_SRC=<patched, built xrdp tree>; libavcodec-dev
	patches/xrdp/test/run_test.sh $(XRDP_SRC) libx264
# (no GPU: the VA-API probe fails and libx264 takes over; without a fallback: refused)
	patches/xrdp/test/run_test.sh $(XRDP_SRC) h264_vaapi
	FALLBACK= patches/xrdp/test/run_test.sh $(XRDP_SRC) h264_vaapi null
	patches/xrdp/test/run_test.sh $(XRDP_SRC) h264_nvenc
	FALLBACK= patches/xrdp/test/run_test.sh $(XRDP_SRC) h264_nvenc null

test-wlroots:   # xvfb xwayland wlr-randr wl-clipboard xclip x11-utils + sway/labwc/wayfire
	tests/wlroots/run.sh

test-e2e:
	tests/proxy-e2e/run.sh

test-e2e-nla:
	tests/proxy-e2e/run_nla.sh

test-e2e-smartcard:   # + krb5-pkinit softhsm2 opensc p11-kit-modules
	tests/proxy-e2e/run_smartcard.sh

# SoftHSM without p11-kit: 32-bit slot ids, fails without patches/freerdp (slot id fix)
test-e2e-smartcard-softhsm:
	SC_MODULE=softhsm tests/proxy-e2e/run_smartcard.sh

# Manual (JDK + Keycloak + Chromium): passkeys on the web path, Keycloak role + webgate.
test-keycloak:   # CHROME=<chromium>, optional KEYCLOAK_HOME/JAVA_HOME; see tests/keycloak/run.sh
	tests/keycloak/run.sh

# LAB ONLY tools under tests/lab that have offline unit tests (totp.py: RFC 6238 vectors,
# secret parsing, fresh-step logic; a5_f19.py: MCP client, plumbing, the F19 sequence
# against fakes; rdpcapture: decode.py and evtx_summary.py on synthetic data; a5-collect.sh
# with stubbed commands); stdlib only (python3-cryptography, python-evtx: more tests run).
test-lab:
	python3 -m unittest -v tests/lab/test_totp.py tests/lab/test_a5_f19.py tests/lab/test_approve.py \
	  tests/lab/test_rdpcapture.py tests/lab/test_a5_collect.py

# Prototype (docs/webauthn-redirection.md): RDPEWA/CTAPHID codecs, stdlib only, not shipped.
test-prototypes:
	cd prototypes/webauthn-redirection && python3 -m unittest discover -s tests

check-krb5-spnego:   # libwinpr3-dev libkrb5-dev krb5-kdc krb5-admin-server; exit 1 = affected
	tests/krb5-spnego/run.sh

lint:   # ansible-lint, shellcheck (missing: SKIP, or FAIL with FASTRDP_TESTS_STRICT=1)
	@$(call with_tool,lint ansible,ansible-lint,cd ansible && ansible-lint site.yml)
	@$(call with_tool,lint shell,shellcheck,\
	  shellcheck -x broker/session/libexec/startwm.sh broker/session/libexec/session-plasma \
		broker/session/libexec/kwin-wayland-launch broker/session/libexec/wlroots-in-x \
		broker/session/libexec/xrdp-audio \
		tests/proxy-e2e/*.sh tests/krb5-spnego/run.sh tests/smoke/*.sh tests/perf/*.sh patches/xrdp/test/run_test.sh \
		third_party/*.sh tests/lib.sh tests/packaging/*.sh tests/keycloak/run.sh tests/lab/*.sh tests/docs/*.sh tests/ansible/*.sh \
		broker/pam_fastrdp_token/test/run_test.sh docs/examples/keycloak-mfa/fastrdp-mfa-kcadm.sh && \
	  shellcheck -e SC1090$(comma)SC2015 tests/wlroots/run.sh && \
	  shellcheck packaging/ci/*.sh packaging/apt/*.sh debian/bin/* broker/sbin/fastrdp-termsrv-* ansible/roles/base/files/*.sh \
		packaging/xrdp/debian/fastrdp-xrdp.postinst packaging/xrdp/debian/fastrdp-xrdp.postrm)
	packaging/ci/check-build-deps.sh

lint-ci:   # actionlint (https://github.com/rhysd/actionlint)
	actionlint .github/workflows/*.yml

deb:   # Debian/Ubuntu packages into ..; build deps: apt-get build-dep ./ (docs/packaging.md)
	dpkg-buildpackage -us -uc -b

# --- setup
# Guided setup (docs/quickstart.md): scripts/fastrdp-setup writes ansible/inventories/<name>/,
# ansible/preflight.yml checks the targets read-only, then site.yml deploys.
#   make setup [SETUP_ARGS='--answers site.json --non-interactive']
#   make preflight INVENTORY=<name|dir> [VAULT_PASSWORD_FILE=<file>] [ANSIBLE_ARGS=-K]
#   make deploy    INVENTORY=<name|dir> [VAULT_PASSWORD_FILE=<file>] [ANSIBLE_ARGS='-K --diff']
#   make test-setup lint-setup         (also part of make test / make lint)
.PHONY: setup preflight deploy test-setup lint-setup setup-inventory-exists
INVENTORY ?=
SETUP_ARGS ?=
ANSIBLE_ARGS ?=
VAULT_PASSWORD_FILE ?=
SETUP_INV = $(abspath $(if $(wildcard $(INVENTORY)/hosts.yml),$(INVENTORY),ansible/inventories/$(INVENTORY)))
SETUP_ANSIBLE_FLAGS = -i $(SETUP_INV)/hosts.yml $(if $(VAULT_PASSWORD_FILE),--vault-password-file $(abspath $(VAULT_PASSWORD_FILE)),$(if $(wildcard $(SETUP_INV)/group_vars/all/vault.yml),--ask-vault-pass)) $(ANSIBLE_ARGS)

setup:
	scripts/fastrdp-setup $(SETUP_ARGS)

setup-inventory-exists:
	@test -n "$(INVENTORY)" || { echo "usage: make $(MAKECMDGOALS) INVENTORY=<name under ansible/inventories, or a directory>"; exit 2; }
	@test -f "$(SETUP_INV)/hosts.yml" || { echo "$(SETUP_INV)/hosts.yml not found (run make setup)"; exit 2; }

preflight: setup-inventory-exists
	cd ansible && ansible-playbook $(SETUP_ANSIBLE_FLAGS) preflight.yml

deploy: setup-inventory-exists
	cd ansible && ansible-playbook $(SETUP_ANSIBLE_FLAGS) site.yml

test-setup:   # PyYAML and ansible-vault are used when installed; shellcheck/ansible-playbook likewise
	python3 -m unittest discover -s scripts/tests

lint-setup:
	@$(call with_tool,lint-setup,ansible-lint,cd ansible && ansible-lint --profile production preflight.yml)

test: test-setup
lint: lint-setup
