# Developer checks. Integration tests need FreeRDP 3.32+ dev files; see tests/proxy-e2e/.
.PHONY: test test-broker test-pam test-gpu test-e2e test-e2e-nla perf-tools perf-proxy lint

test: test-broker test-pam test-gpu lint

test-broker:
	cd broker/brokerd && python3 -m unittest discover -s tests

test-pam:
	$(MAKE) -C broker/pam_fastrdp_token check

test-gpu:
	cd tests/gpu && python3 -m unittest test_session_report

perf-tools:
	$(MAKE) -C tests/perf/rdpbench

perf-proxy:
	tests/perf/proxy-overhead.sh 15 3

test-e2e:
	tests/proxy-e2e/run.sh

test-e2e-nla:
	tests/proxy-e2e/run_nla.sh

lint:
	cd ansible && ansible-lint site.yml
	shellcheck broker/session/libexec/* tests/proxy-e2e/*.sh tests/smoke/*.sh tests/perf/*.sh
