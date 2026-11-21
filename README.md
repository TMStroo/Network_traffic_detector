# Network Traffic Analyzer

Reads classic PCAP network captures and finds unusual communication patterns.

It parses Ethernet, IPv4, IPv6, TCP, UDP, DNS and HTTP metadata. It rebuilds
network conversations, groups activity by host, creates timelines, compares
multiple captures and explains why detected events deserve investigation.

## Stack

- C++20 for packet parsing, flow tracking and detection
- SQLite for saved results and cross-capture correlation
- Python 3 for statistical analysis
- Scapy for optional independent capture validation
- CMake for building and testing

The C++ reader currently supports classic PCAP files. The Scapy validation
tool also reads PCAPNG files. PCAPNG support in the main reader is a separate
development task.

## Build

Install CMake, a C++20 compiler and SQLite development files.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

The executable is `build/nta`.

## Usage

All commands accept `--db PATH`. The default database is `analyze.db`.

```sh
./build/nta analyze tests/sample.pcap --db analyze.db --reset
./build/nta hosts --db analyze.db
./build/nta conversations --db analyze.db --protocol tcp
./build/nta timeline --db analyze.db --limit 50
./build/nta dns --db analyze.db
./build/nta anomalies --db analyze.db
./build/nta stats --db analyze.db
./build/nta report --db analyze.db
./build/nta correlate --db analyze.db
```

## Detection

The current detectors look for:

- DNS tunneling patterns
- High DNS NXDOMAIN rates
- Port scanning
- Periodic beacon-like traffic
- Large transfers and possible data exfiltration
- Bursts of HTTP errors
- Unusual protocol and port combinations

Each finding includes evidence and an explanation. Findings are leads for
investigation, not proof of malicious activity.

## Project structure

```
src/
  main.cpp
  cli.cpp / cli.h
  pcap.cpp / pcap.h
  packet.cpp / packet.h
  conversation.cpp / conversation.h
  storage.cpp / storage.h
  detector.cpp / detector.h
  timeline.cpp / timeline.h
  correlator.cpp / correlator.h
  python_stats.cpp / python_stats.h
python/
  nta_stats.py
tools/
  gen_test_pcap.py
  validate_pcap.py
tests/
  sample.pcap
  test_packet.cpp
  test_pcap.cpp
```

## Tests

```sh
ctest --test-dir build --output-on-failure
python3 tools/gen_test_pcap.py -o tests/sample.pcap
./build/nta analyze tests/sample.pcap --db tests/test.db --reset
./build/nta anomalies --db tests/test.db
```

For an independent capture check, install Scapy:

```sh
python3 -m pip install scapy
python3 tools/validate_pcap.py tests/sample.pcap
```

Scapy is not used by the C++ parser. The validator provides a second
implementation to compare packet and protocol counts.
