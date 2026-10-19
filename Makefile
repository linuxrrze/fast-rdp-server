# Developer checks. Integration tests need FreeRDP 3.32+ dev files; see tests/proxy-e2e/.
# Overview of every test, what it guards and where CI runs it: tests/README.md.
.PHONY: deb test-xrdp-encoder test-wlroots test test-all test-broker test-webgate test-pam test-gpu \
	test-scripts test-publish test-ansible test-e2e test-e2e-nla test-e2e-smartcard \
	test-e2e-smartcard-softhsm check-krb5-spnego perf-tools perf-proxy lint lint-ci

test: test-broker test-webgate test-pam test-gpu lint

# Everything that runs locally without root (missing tools: SKIP, or FAIL with
# FASTRDP_TESTS_STRICT=1). Needs libpam0g-dev, python3-cryptography, ansible-core,
# ansible-lint, shellcheck, dpkg-dev, curl, reprepro, gnupg, apt.
test-all: test test-scripts test-publish test-ansible

test-broker:
	cd broker/brokerd && python3 -m unittest discover -s tests

test-webgate:   # needs python3-cryptography
	cd broker/webgate && python3 -m unittest discover -s tests

test-pam:
	$(MAKE) -C broker/pam_fastrdp_token check

test-gpu:
	cd tests/gpu && python3 -m unittest test_session_report

test-scripts:   # fetch.sh, build-key.sh, packaging/ci/*.sh; dpkg-dev curl patch xz-utils
	tests/packaging/test_fetch.sh
	tests/packaging/test_build_key.sh
	tests/packaging/test_ci_scripts.sh

test-publish:   # packaging/apt/publish.sh + apt-get update; reprepro gnupg dpkg-dev apt
	tests/packaging/test_publish.sh

test-ansible:   # ansible-core; syntax check + role templates rendered and parsed
	cd ansible && ansible-playbook --syntax-check site.yml
	python3 -m unittest -v tests/ansible/test_templates.py

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

check-krb5-spnego:   # libwinpr3-dev libkrb5-dev krb5-kdc krb5-admin-server; exit 1 = affected
	tests/krb5-spnego/run.sh

lint:
	cd ansible && ansible-lint site.yml
	shellcheck -x broker/session/libexec/startwm.sh broker/session/libexec/session-plasma \
		broker/session/libexec/kwin-wayland-launch broker/session/libexec/wlroots-in-x \
		tests/proxy-e2e/*.sh tests/krb5-spnego/run.sh tests/smoke/*.sh tests/perf/*.sh patches/xrdp/test/run_test.sh \
		third_party/*.sh tests/lib.sh tests/packaging/*.sh
	shellcheck -e SC1090,SC2015 tests/wlroots/run.sh
	shellcheck packaging/ci/*.sh packaging/apt/*.sh debian/bin/*
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
	cd ansible && ansible-lint --profile production preflight.yml

test: test-setup
lint: lint-setup
