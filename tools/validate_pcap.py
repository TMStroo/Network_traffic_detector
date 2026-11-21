#!/usr/bin/env python3
"""Check a capture with Scapy and print a compact protocol summary.

Scapy is used as an independent PCAP reader. The main analyzer still parses
packets in C++, so its parsing logic remains visible and testable.
"""

import argparse
from collections import Counter

from scapy.all import DNS, Ether, IP, IPv6, TCP, UDP, rdpcap


def main():
    parser = argparse.ArgumentParser(
        description="Validate a PCAP/PCAPNG file with Scapy"
    )
    parser.add_argument("capture", help="Path to a PCAP or PCAPNG file")
    args = parser.parse_args()

    try:
        packets = rdpcap(args.capture)
    except Exception as error:
        parser.error("Scapy could not read the capture: %s" % error)

    counts = Counter()
    for packet in packets:
        counts["packets"] += 1
        if Ether in packet:
            counts["ethernet"] += 1
        if IP in packet:
            counts["ipv4"] += 1
        if IPv6 in packet:
            counts["ipv6"] += 1
        if TCP in packet:
            counts["tcp"] += 1
        if UDP in packet:
            counts["udp"] += 1
        if DNS in packet:
            counts["dns"] += 1

    print("Scapy capture summary")
    print("---------------------")
    for name in ("packets", "ethernet", "ipv4", "ipv6", "tcp", "udp", "dns"):
        print("%-10s %d" % (name + ":", counts[name]))

    if counts["packets"] == 0:
        print("Warning: the capture contains no packets.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
