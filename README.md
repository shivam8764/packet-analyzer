# Packet Analyzer

![CI](https://github.com/shivam8764/packet-analyzer/actions/workflows/ci.yml/badge.svg)

A lightweight network packet analyzer written in C using libpcap. Captures live traffic and dissects Ethernet, IPv4, TCP, UDP, and ICMP layers with colored, human-readable output.

## Dependencies

- **gcc** (or any C99 compiler)
- **make**
- **libpcap-dev** — packet capture library
- **valgrind** — memory leak checking (for development/CI)

### Install on Debian/Ubuntu

```bash
sudo apt-get install gcc make libpcap-dev valgrind
```

### Install on macOS

```bash
brew install libpcap
```

## Build

```bash
make all        # Build the analyzer binary
make test       # Build and run unit tests
make clean      # Remove build artifacts
```

## Usage

```
./analyzer <interface> [packet_count] [filter_expression]
./analyzer --list
```

The binary requires root/sudo privileges for raw socket access.

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

**Capture only DNS (UDP port 53) traffic:**

```bash
sudo ./analyzer eth0 0 "udp port 53"
```

**Capture TCP traffic on port 443:**

```bash
sudo ./analyzer eth0 50 "tcp port 443"
```

**Capture ICMP packets (ping):**

```bash
sudo ./analyzer eth0 0 "icmp"
```

All captured packets are also written to `capture.log` in the working directory.

## BPF Filter Expressions

Any valid BPF filter expression can be passed as the third argument:

| Filter | Description |
|--------|-------------|
| `tcp` | All TCP packets |
| `udp` | All UDP packets |
| `icmp` | All ICMP packets |
| `tcp port 80` | HTTP traffic |
| `udp port 53` | DNS traffic |
| `host 192.168.1.1` | Traffic to/from a host |
| `src host 10.0.0.1` | Traffic from a specific source |
| `tcp and port 443` | HTTPS traffic |

## Running Tests

Tests exercise the packet parser with hand-crafted byte arrays and do not require root or a live network interface:

```bash
make test
```

```
=== Packet Parser Unit Tests ===

[PASS] ethernet: NULL packet returns -1
[PASS] ethernet: zero-length packet returns -1
[PASS] tcp_syn: SYN flag set
...

=== Results: 35/35 passed ===
```

## CI/CD

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push to `main` or `dev`:

1. Installs dependencies
2. Builds with `make all`
3. Runs unit tests with `make test`
4. Checks for memory leaks with Valgrind
5. Recompiles with `-Werror` to catch warnings

## Project Structure

```
packet-analyzer/
├── .github/workflows/ci.yml   # CI/CD pipeline
├── src/
│   ├── main.c                 # CLI entry point
│   ├── capture.c              # libpcap capture logic
│   ├── capture.h
│   ├── parser.c               # Protocol dissectors
│   └── parser.h
├── tests/
│   └── test_parser.c          # Unit tests (no root required)
├── Makefile
└── README.md
```

## License

MIT
