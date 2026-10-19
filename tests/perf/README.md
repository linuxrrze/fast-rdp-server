# Performance measurement

The method, tools, measured results and GPU behaviour per back-end are in
[docs/performance.md](../../docs/performance.md).

```sh
make -C tests/perf/rdpbench                 # rdpbench + perfload
tests/perf/proxy-overhead.sh 15 3           # proxy cost on any Linux box (Xvfb + shadow server)
sudo tests/perf/compare-host.sh alice 'pw'  # direct vs. proxied on a deployed host
```

## Results template (`tests/perf/results/<date>-<host>.md`)

```
Host: CPU, RAM, GPU (+ driver version), distro
fastrdp commit:            inventory: fastrdp_gpu, fastrdp_x264_*, fastrdp_krdp_*
Client: OS, FreeRDP version + `/buildconfig | grep GFX_H264`, network (LAN/WAN, RTT)

| desktop | load | sessions | fps avg/peak | codec | Mbit/s | latency p50/p95 | server CPU | GPU enc % | session_report verdict |
|---|---|---|---|---|---|---|---|---|---|
```
