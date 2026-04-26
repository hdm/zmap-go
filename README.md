zmap-go
=======

> ⚠️ **Experimental.** This is an unofficial, experimental port of [ZMap](https://github.com/zmap/zmap) — the fast stateless single-packet Internet scanner from the University of Michigan — from C to Go. It is not affiliated with or endorsed by the upstream ZMap project. Expect rough edges, missing features, and behaviour that diverges from upstream in subtle ways. Do not rely on it for production measurement work yet.

* **Upstream (canonical) ZMap, in C:** <https://github.com/zmap/zmap>
* **This port:** Go module `github.com/hdm/zmap-go`

Goals
-----

* Pure Go, `CGO_ENABLED=0` on Linux, the BSDs, macOS, and Windows (Windows uses `gopacket/pcap`, which dynamically loads `wpcap.dll` from [Npcap](https://npcap.com) at runtime — no C toolchain needed at build time).
* Installable with a single `go install`.
* Embeddable as a library — every component lives under `pkg/...`.
* Behavioural compatibility with upstream ZMap where practical (probe validation, sharding, output fields).

What works today
----------------

* Probe modules: `tcp_synscan`, `tcp_synackscan`, `icmp_echo`, `icmp_echo_time`, `udp`, `dns`, `ntp`
* Output modules: `default` (one IP per line), `csv`, `json`
* Sharding (`--shards` / `--shard` / `--seed`) and `--dryrun`
* AES-128 probe validation matching upstream's per-probe seq/id derivation
* Raw L2 send/recv: `AF_PACKET` (Linux), `/dev/bpf*` (BSD/macOS), Npcap's `wpcap.dll` (Windows)
* Automatic gateway-MAC resolution via the OS routing table + ARP
* Multi-threaded sender (default `runtime.NumCPU()-1` goroutines)
* Companion tools: `ziterate`, `zblocklist`, `ztee`

What is missing or different from upstream
------------------------------------------

* Many specialty UDP probe modules (UPnP, BACNET, etc.) are not yet ported.
* No `--config` file, no PF_RING / netmap, no monitor/progress UI.
* Logger, status output, and metrics are minimal.
* CLI flag set is a deliberate subset; behaviour may differ in edge cases.

Install
-------

Requires Go 1.25+.

```sh
go install github.com/hdm/zmap-go/cmd/zmap@latest
go install github.com/hdm/zmap-go/cmd/ziterate@latest
go install github.com/hdm/zmap-go/cmd/zblocklist@latest
go install github.com/hdm/zmap-go/cmd/ztee@latest
```

On Windows, install [Npcap](https://npcap.com) first.

Sending raw L2 packets needs privileges:

* Linux: `sudo` or `setcap cap_net_raw,cap_net_admin=eip $(which zmap)`
* macOS / BSD: `sudo` (or grant access to `/dev/bpf*`)
* Windows: run as Administrator

Quick start
-----------

```sh
# Dry-run a TCP-80 sweep so you can see what would be sent
zmap --dryrun -O csv -p 80 -n 5 192.0.2.0/24

# Real scan, JSON output
sudo zmap -p 80 -O json -n 1000 192.0.2.0/24

# DNS A-record probe
sudo zmap -M dns --probe-args example.com -p 53 -O json 192.0.2.0/24
```

Run `zmap -h` for the full flag list.

Library use
-----------

```go
import (
    "github.com/hdm/zmap-go/pkg/blocklist"
    "github.com/hdm/zmap-go/pkg/cyclic"
    "github.com/hdm/zmap-go/pkg/iterator"
    "github.com/hdm/zmap-go/pkg/shard"
)
```

Packages of interest:

| Package                                  | Purpose                                          |
| ---------------------------------------- | ------------------------------------------------ |
| `pkg/iterator`, `pkg/shard`, `pkg/cyclic` | Cyclic-group target iterator and sharding        |
| `pkg/blocklist`                          | CIDR allow/block-list                            |
| `pkg/validate`                           | AES-128 probe validation                         |
| `pkg/packet`                             | Probe-packet builders (TCP/UDP/ICMP/ARP/DNS/NTP) |
| `pkg/probe`                              | Probe modules (send + validate)                  |
| `pkg/output`                             | Pluggable result writers                         |
| `pkg/raw`                                | Cross-platform raw L2 socket                     |
| `pkg/gateway`                            | Default-route discovery + ARP MAC resolution     |

Ethics
------

Internet-wide scanning has real consequences. Scan at the slowest rate that meets your needs, narrow your target space, honour blocklists, and offer an opt-out. See upstream's [Scanning Best Practices](https://github.com/zmap/zmap/wiki/Scanning-Best-Practices).

Citing ZMap
-----------

If you publish research using any descendant of ZMap (this port included), please cite the original paper:

```
@inproceedings{durumeric2013zmap,
  title={{ZMap}: Fast Internet-wide scanning and its security applications},
  author={Durumeric, Zakir and Wustrow, Eric and Halderman, J Alex},
  booktitle={22nd USENIX Security Symposium},
  year={2013}
}
```

License
-------

Apache License 2.0. See [LICENSE](LICENSE). The original C ZMap is © 2024 Regents of the University of Michigan; this port keeps the same license and credits the upstream authors.
