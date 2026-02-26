# Packet Analyzer

![CI](https://github.com/shivam8764/packet-analyzer/actions/workflows/ci.yml/badge.svg)
![Language](https://img.shields.io/badge/language-C-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

A lightweight, zero-dependency (beyond libpcap) network packet analyzer written in C. Captures live traffic from any network interface and dissects packets across multiple protocol layers with human-readable output and file logging.

---

## Features

- **Live packet capture** using libpcap with configurable packet count
- **Multi-layer dissection** — Ethernet, IPv4, TCP, UDP, and ICMP
- **BPF filter support** — use any Berkeley Packet Filter expression to narrow traffic
- **Dual output** — simultaneous stdout display and `capture.log` file logging
- **Interface discovery** — list all available network interfaces with `--list`
- **Graceful shutdown** — Ctrl+C cleanly stops capture via `pcap_breakloop`
- **Memory safe** — zero leaks verified by Valgrind in CI
- **Warning free** — compiles cleanly with `-Wall -Wextra -Werror`

## Protocol Support

| Layer | Protocol | Fields Parsed |
|-------|----------|---------------|
| L2 | Ethernet | Source MAC, Destination MAC, EtherType (IPv4/IPv6/ARP) |
| L3 | IPv4 | Source IP, Destination IP, TTL, Protocol number |
| L3 | ICMP | Type, Code |
| L4 | TCP | Source Port, Destination Port, Flags (SYN/ACK/FIN/RST) |
| L4 | UDP | Source Port, Destination Port, Length |

---

## Requirements

| Dependency | Purpose | Required |
|------------|---------|----------|
| **gcc** (or any C99 compiler) | Compilation | Yes |
| **make** | Build system | Yes |
| **libpcap-dev** | Packet capture library | Yes |
| **valgrind** | Memory leak detection | Dev/CI only |

### Install on Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y gcc make libpcap-dev valgrind
```

### Install on Fedora/RHEL

```bash
sudo dnf install gcc make libpcap-devel valgrind
```

### Install on Arch Linux

```bash
sudo pacman -S gcc make libpcap valgrind
```

### Install on macOS

```bash
# libpcap ships with macOS; install Xcode CLI tools for gcc/make
xcode-select --install
# Optional: install valgrind via Homebrew (macOS support is limited)
brew install valgrind
```

---

## Build

```bash
git clone https://github.com/shivam8764/packet-analyzer.git
cd packet-analyzer
make all
```

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make all` | Compiles the `analyzer` binary (links against libpcap) |
| `make test` | Compiles and runs the unit test suite (no root, no libpcap needed) |
| `make clean` | Removes all build artifacts, binaries, and log files |

**Compiler flags:** `-Wall -Wextra -g` (debug symbols included by default)

---

## Usage

```
./analyzer <interface> [packet_count] [filter_expression]
./analyzer --list
```

| Argument | Description | Default |
|----------|-------------|---------|
| `interface` | Network interface to capture on (e.g., `eth0`, `wlan0`, `lo`) | *required* |
| `packet_count` | Number of packets to capture; `0` = unlimited | `0` |
| `filter_expression` | BPF filter string (quoted) | none (all traffic) |

> **Note:** The binary requires `sudo` (root privileges) for raw socket access. Tests do **not** require root.

### Examples

**List available interfaces:**

```bash
sudo ./analyzer --list
```

```
Available network interfaces:
  1. eth0  (Ethernet)
  2. lo  (Loopback)
  3. wlan0
```

**Capture 10 packets on eth0:**

```bash
sudo ./analyzer eth0 10
```

```
Capturing on eth0 (max 10 packets)
Press Ctrl+C to stop...

========== Packet #1 (74 bytes) ==========
  Ethernet: aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66  EtherType: 0x0800 (IPv4)
  IPv4: 192.168.1.100 -> 93.184.216.34  TTL=64  Protocol=6
  TCP: 52431 -> 443  Flags: [SYN ]

========== Packet #2 (66 bytes) ==========
  Ethernet: 11:22:33:44:55:66 -> aa:bb:cc:dd:ee:ff  EtherType: 0x0800 (IPv4)
  IPv4: 93.184.216.34 -> 192.168.1.100  TTL=52  Protocol=6
  TCP: 443 -> 52431  Flags: [SYN ACK ]

10 packet(s) captured.
```

**Capture only DNS traffic:**

```bash
sudo ./analyzer eth0 0 "udp port 53"
```

**Capture HTTPS traffic (limited to 50 packets):**

```bash
sudo ./analyzer eth0 50 "tcp port 443"
```

**Capture ICMP packets (ping):**

```bash
sudo ./analyzer eth0 0 "icmp"
```

**Capture traffic to/from a specific host:**

```bash
sudo ./analyzer eth0 0 "host 192.168.1.1"
```

All captured packets are automatically logged to `capture.log` in the working directory.

---

## BPF Filter Expressions

Any valid [Berkeley Packet Filter](https://www.tcpdump.org/manpages/pcap-filter.7.html) expression can be passed as the third argument:

| Filter | Description |
|--------|-------------|
| `tcp` | All TCP packets |
| `udp` | All UDP packets |
| `icmp` | All ICMP packets |
| `arp` | All ARP packets |
| `tcp port 80` | HTTP traffic |
| `tcp port 443` | HTTPS traffic |
| `udp port 53` | DNS traffic |
| `host 192.168.1.1` | Traffic to/from a specific host |
| `src host 10.0.0.1` | Traffic from a specific source |
| `dst port 22` | Traffic to SSH port |
| `tcp and port 443` | Compound filter for HTTPS |
| `not port 22` | Exclude SSH traffic |
| `portrange 8000-9000` | Traffic on a port range |

---

## Testing

The test suite exercises the packet parser with hand-crafted byte arrays and validates boundary checks, protocol parsing correctness, and crash resistance. Tests require **no root privileges** and **no live network interface**.

```bash
make test
```

```
=== Packet Parser Unit Tests ===

[PASS] ethernet: NULL packet returns -1
[PASS] ethernet: zero-length packet returns -1
[PASS] ethernet: 10-byte packet returns -1
[PASS] ipv4: 10-byte packet returns -1
[PASS] ipv4: version != 4 returns -1
[PASS] ipv4: ihl exceeds length returns -1
[PASS] tcp: 10-byte data returns -1
[PASS] udp: 4-byte data returns -1
[PASS] icmp: 2-byte data returns -1
[PASS] ipv4: NULL data returns -1
[PASS] tcp: NULL data returns -1
[PASS] udp: NULL data returns -1
[PASS] icmp: NULL data returns -1
[PASS] arp: parse succeeds
[PASS] arp: ethertype is 0x0806
[PASS] arp: dst MAC is broadcast
[PASS] arp: src MAC parsed correctly
[PASS] tcp_syn: parse succeeds
[PASS] tcp_syn: src port is 12345
[PASS] tcp_syn: dst port is 443
[PASS] tcp_syn: SYN flag set
[PASS] tcp_syn: ACK flag not set
[PASS] tcp_syn: FIN flag not set
[PASS] tcp_syn: RST flag not set
[PASS] tcp_synack: parse succeeds
[PASS] tcp_synack: SYN flag set
[PASS] tcp_synack: ACK flag set
[PASS] tcp_finack: parse succeeds
[PASS] tcp_finack: FIN flag set
[PASS] tcp_finack: ACK flag set
[PASS] tcp_finack: SYN flag not set
[PASS] tcp_rst: parse succeeds
[PASS] tcp_rst: RST flag set
[PASS] tcp_rst: SYN flag not set
[PASS] tcp_rst: ACK flag not set
[PASS] udp: parse succeeds
[PASS] udp: src port is 53
[PASS] udp: dst port is 1024
[PASS] udp: length is 512
[PASS] format_mac: correct output
[PASS] format_ipv4: correct output
[PASS] print_packet: no crash on malformed data

=== Results: 42/42 passed ===
```

### Test Categories

| Category | Tests | What's Verified |
|----------|-------|-----------------|
| Boundary checks | 13 | Short packets, NULL pointers, bad versions, oversized headers |
| ARP parsing | 4 | EtherType identification, MAC address extraction |
| TCP flags | 15 | SYN, SYN+ACK, FIN+ACK, RST — individual and combined flags |
| UDP parsing | 4 | Port numbers, datagram length |
| Format helpers | 2 | MAC and IPv4 address string formatting |
| Crash resistance | 4 | Malformed data passed through full print_packet pipeline |

---

## CI/CD Pipeline

The GitHub Actions workflow runs automatically on every push or pull request to `main` or `dev`.

| Step | Description |
|------|-------------|
| **Checkout** | Clones the repository |
| **Install deps** | `apt-get install libpcap-dev valgrind gcc make` |
| **Build** | `make all` — compiles the analyzer binary |
| **Test** | `make test` — runs all 42 unit tests |
| **Valgrind** | `valgrind --leak-check=full --error-exitcode=1 ./test_runner` — fails on any memory leak |
| **Strict compile** | `make all CFLAGS="-Wall -Wextra -Werror -g"` — fails on any compiler warning |

---

## Architecture

```
packet-analyzer/
├── .github/
│   └── workflows/
│       └── ci.yml              # GitHub Actions CI pipeline
├── src/
│   ├── main.c                  # CLI argument parsing, signal handling, entry point
│   ├── capture.c               # libpcap session management (open, filter, loop, close)
│   ├── capture.h               # Capture context struct and function declarations
│   ├── parser.c                # Protocol dissectors and output formatting
│   └── parser.h                # Parser structs (eth, ip, tcp, udp, icmp) and API
├── tests/
│   └── test_parser.c           # 42 unit tests with hand-crafted packet buffers
├── .gitignore
├── Makefile                    # Build targets: all, test, clean
└── README.md
```

### Design Decisions

- **Pointer casting over raw buffers** — protocol headers are accessed by casting `uint8_t*` to struct pointers, avoiding `memcpy` overhead for read-only access
- **Network byte order** — all multi-byte fields converted with `ntohs()`/`ntohl()` at parse time
- **No global mutable state** — all capture state lives in `capture_ctx_t`; the only global is the `pcap_t*` pointer in `main.c` for the SIGINT handler
- **Separated parser from capture** — `parser.c` has no libpcap dependency, enabling unit tests to link without it and run without root
- **Defensive parsing** — every parser function validates minimum required length before reading any bytes, preventing buffer over-reads on malformed/truncated packets

---

## License

MIT
