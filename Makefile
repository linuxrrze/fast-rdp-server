# Developer checks. Integration tests need FreeRDP 3.32+ dev files; see tests/proxy-e2e/.
.PHONY: test test-broker test-pam test-e2e test-e2e-nla lint

test: test-broker test-pam lint

test-broker:
	cd broker/brokerd && python3 -m unittest discover -s tests

test-pam:
	$(MAKE) -C broker/pam_fastrdp_token check

test-e2e:
	tests/proxy-e2e/run.sh

test-e2e-nla:
	tests/proxy-e2e/run_nla.sh

lint:
	cd ansible && ansible-lint site.yml
	shellcheck broker/session/libexec/* tests/proxy-e2e/*.sh tests/smoke/*.sh
