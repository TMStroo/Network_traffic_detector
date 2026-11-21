#!/usr/bin/env python3
"""Generates a synthetic PCAP with normal traffic and a few anomalies.

Scenarios injected for testing:
  * normal DNS queries and web browsing
  * beaconing: periodic TCP connections between two hosts
  * port scan: one source dialing many ports on one host within a short window
  * DNS tunneling: many unique, long-looking DNS query names from one host
  * data exfiltration: large internal-to-external transfer
  * HTTP errors: burst of 404 responses
  * IPv6 web traffic

Usage: python3 tools/gen_test_pcap.py [-o tests/sample.pcap]
"""

import argparse
import random
import socket
import struct

T0 = 1795915200  # fixed base time, seconds since the Unix epoch
BASE_US = T0 * 1000000  # same base, in microseconds (for packet timestamps)

CLIENT = "10.0.0.5"
CLIENT_MAC = "02:00:00:00:00:05"
DNS = "8.8.8.8"
DNS_MAC = "02:00:00:00:00:08"
WEB_SERVER = "93.184.216.34"
WEB_SERVER_MAC = "02:00:00:00:00:34"
WEB_SERVER2 = "93.184.216.35"
EXFIL_HOST = "198.51.100.9"
EXFIL_MAC = "02:00:00:00:00:09"
INTERNAL_HOST = "10.0.0.7"
INTERNAL_MAC = "02:00:00:00:00:07"
IPV6_CLIENT = "fe80::1"
IPV6_CLIENT_MAC = "02:00:00:00:00:05"
IPV6_SERVER = "2606:2800:220:1:248:1893:25c8:1946"
IPV6_SERVER_MAC = "02:00:00:00:00:46"

SYN, SYNACK, ACK, PSHACK, FIN = 2, 0x12, 16, 0x18, 1
ETHERNET = 0x0800


def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))


def eth(src_mac, dst_mac, ethertype):
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack(">H", ethertype)


def ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    return struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total, 0x4321, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    ) + payload


def ipv6(src, dst, proto, payload):
    return struct.pack(
        ">IHBB16s16s",
        0x60000000,  # version 6, traffic class 0, flow label 0
        len(payload),
        proto,
        64,
        socket.inet_pton(socket.AF_INET6, src),
        socket.inet_pton(socket.AF_INET6, dst),
    ) + payload


def tcp(sport, dport, seq, ack, flags, payload=b""):
    return (
        struct.pack(">HHIIB", sport, dport, seq, ack, 5 << 4)
        + struct.pack(">B", flags)
        + struct.pack(">HHH", 64, 0, 0)
        + payload
    )


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_name(name):
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".") if l) + b"\x00"


def dns_query(txid, name, qtype, flags=0x0100):
    return struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0) + dns_name(name) + struct.pack(">HH", qtype, 1)


def a_record(ip, ttl=300):
    return (1, socket.inet_aton(ip), ttl)


def dns_response(txid, name, answers, flags=0x8180):
    out = struct.pack(">HHHHHH", txid, flags, 1, len(answers), 0, 0)
    out += dns_name(name) + struct.pack(">HH", 1, 1)
    for rtype, rdata, ttl in answers:
        out += struct.pack(">HHHIH", 0xC00C, rtype, 1, ttl, len(rdata)) + rdata
    return out


def http_request(method, path, host, user_agent):
    return (
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "\r\n"
    ) % (method, path, host, user_agent)


def http_response(status, body=b"", server="nginx", ctype="text/html"):
    return (
        "HTTP/1.1 %d OK\r\n"
        "Server: %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "\r\n"
    ).encode() % (status, server.encode(), ctype.encode(), len(body)) + body


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack(">IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1000000))
            f.write(struct.pack(">IIII", sec, usec, len(data), len(data)))
            f.write(data)


# ---------------------------------------------------------------------------

def normal_web(t):
    """Normal DNS queries and web browsing between two hosts."""
    pkts = []
    txid = 100
    for i, name in enumerate(["www.example.com", "api.github.com", "dns.google"]):
        ip = WEB_SERVER
        q = dns_query(txid, name, 1)
        pkts.append((t + i, eth(CLIENT_MAC, DNS_MAC, ETHERNET) + ipv4(CLIENT, DNS, 17, udp(41000 + i, 53, q))))
        r = dns_response(txid, name, [a_record(ip)])
        pkts.append((t + i + 0.5, eth(DNS_MAC, CLIENT_MAC, ETHERNET) + ipv4(DNS, CLIENT, 17, udp(53, 41000 + i, r))))
        txid += 1
    base = t + 10
    cport, dport = 45000, 80
    cseq, sseq = 1000, 1000
    pkts.append((base, eth(CLIENT_MAC, WEB_SERVER_MAC, ETHERNET) + ipv4(CLIENT, WEB_SERVER, 6, tcp(cport, dport, cseq, 0, SYN))))
    cseq += 1
    pkts.append((base + 1, eth(WEB_SERVER_MAC, CLIENT_MAC, ETHERNET) + ipv4(WEB_SERVER, CLIENT, 6, tcp(dport, cport, sseq, cseq, SYNACK))))
    sseq += 1
    pkts.append((base + 2, eth(CLIENT_MAC, WEB_SERVER_MAC, ETHERNET) + ipv4(CLIENT, WEB_SERVER, 6, tcp(cport, dport, cseq, sseq, ACK))))
    for i in range(2):
        req = http_request("GET", "/page%d" % i, WEB_SERVER, "Mozilla/5.0 (X11; Linux x86_64)")
        pkts.append((base + 3 + i * 3, eth(CLIENT_MAC, WEB_SERVER_MAC, ETHERNET) + ipv4(CLIENT, WEB_SERVER, 6, tcp(cport, dport, cseq, sseq, PSHACK, req.encode()))))
        cseq += len(req)
        resp = http_response(200, b"<html><body>hello %d</body></html>" % i)
        pkts.append((base + 4 + i * 3, eth(WEB_SERVER_MAC, CLIENT_MAC, ETHERNET) + ipv4(WEB_SERVER, CLIENT, 6, tcp(dport, cport, sseq, cseq, PSHACK, resp))))
        sseq += len(resp)
    pkts.append((base + 20, eth(CLIENT_MAC, WEB_SERVER_MAC, ETHERNET) + ipv4(CLIENT, WEB_SERVER, 6, tcp(cport, dport, cseq, sseq, FIN))))
    return pkts


def beaconing(t):
    """Periodic TCP connections from one host to one host."""
    pkts = []
    cport, dport = 41000, 443
    seq = 5000
    pkts.append((t, eth(CLIENT_MAC, "02:00:00:00:00:34", ETHERNET) + ipv4(CLIENT, "203.0.113.7", 6, tcp(cport, dport, seq, 0, SYN))))
    for i in range(10):
        pkts.append((t + 15 * (i + 1), eth(CLIENT_MAC, "02:00:00:00:00:34", ETHERNET) + ipv4(CLIENT, "203.0.113.7", 6, tcp(cport, dport, seq + 1 + i * 5, 0, PSHACK, b"ping\n"))))
    return pkts


def port_scan(t):
    """One source dialing many destination ports on one host."""
    pkts = []
    target = INTERNAL_HOST
    for i, port in enumerate([10, 20, 21, 22, 23, 25, 80, 110, 143, 3306]):
        pkts.append((t + i * 0.5, eth(CLIENT_MAC, INTERNAL_MAC, ETHERNET) + ipv4(CLIENT, target, 6, tcp(41000, port, 9000 + i, 0, SYN))))
    return pkts


def dns_tunnel(t, rng):
    """Many unique, long-looking DNS queries from one host."""
    pkts = []
    txid = 500
    for i in range(14):
        hexs = "".join(rng.choice("0123456789abcdef") for _ in range(24))
        name = "%s.tunnel.example.org" % hexs
        q = dns_query(txid + i, name, 1)
        pkts.append((t + i, eth(CLIENT_MAC, DNS_MAC, ETHERNET) + ipv4(CLIENT, DNS, 17, udp(41000, 53, q))))
    return pkts


def data_exfil(t):
    """A large internal-to-external transfer."""
    pkts = []
    cport, dport, seq = 52000, 8443, 20000
    pkts.append((t, eth(CLIENT_MAC, EXFIL_MAC, ETHERNET) + ipv4(CLIENT, EXFIL_HOST, 6, tcp(cport, dport, seq, 0, SYN))))
    for i in range(60):
        pkts.append((t + 1 + i * 0.05, eth(CLIENT_MAC, EXFIL_MAC, ETHERNET) + ipv4(CLIENT, EXFIL_HOST, 6, tcp(cport, dport, seq + 1 + i * 1000, 0, PSHACK, b"A" * 1000))))
    return pkts


def http_errors(t):
    """Burst of 404 responses from one web server."""
    pkts = []
    base = t
    cport, dport = 41000, 80
    cseq, sseq = 7000, 7000
    pkts.append((base, eth(CLIENT_MAC, WEB_SERVER_MAC, ETHERNET) + ipv4(CLIENT, WEB_SERVER2, 6, tcp(cport, dport, cseq, 0, SYN))))
    cseq += 1
    pkts.append((base + 1, eth(WEB_SERVER_MAC, CLIENT_MAC, ETHERNET) + ipv4(WEB_SERVER2, CLIENT, 6, tcp(dport, cport, sseq, cseq, SYNACK))))
    sseq += 1
    pkts.append((base + 2, eth(CLIENT_MAC, WEB_SERVER_MAC, ETHERNET) + ipv4(CLIENT, WEB_SERVER2, 6, tcp(cport, dport, cseq, sseq, ACK))))
    for i in range(4):
        req = http_request("GET", "/missing%d" % i, WEB_SERVER2, "Mozilla/5.0")
        pkts.append((base + 3 + i * 2, eth(CLIENT_MAC, WEB_SERVER_MAC, ETHERNET) + ipv4(CLIENT, WEB_SERVER2, 6, tcp(cport, dport, cseq, sseq, PSHACK, req.encode()))))
        cseq += len(req)
        resp = http_response(404, b"not found")
        pkts.append((base + 4 + i * 2, eth(WEB_SERVER_MAC, CLIENT_MAC, ETHERNET) + ipv4(WEB_SERVER2, CLIENT, 6, tcp(dport, cport, sseq, cseq, PSHACK, resp))))
        sseq += len(resp)
    return pkts


def ipv6_web(t):
    """IPv6 web traffic."""
    pkts = []
    base = t
    cport, dport, seq = 53000, 80, 30000
    pkts.append((base, eth(IPV6_CLIENT_MAC, IPV6_SERVER_MAC, 0x86DD) + ipv6(IPV6_CLIENT, IPV6_SERVER, 6, tcp(cport, dport, seq, 0, SYN))))
    pkts.append((base + 1, eth(IPV6_SERVER_MAC, IPV6_CLIENT_MAC, 0x86DD) + ipv6(IPV6_SERVER, IPV6_CLIENT, 6, tcp(dport, cport, seq + 1, seq + 1, SYNACK))))
    req = http_request("GET", "/ipv6", "[2606:2800:220:1:248:1893:25c8:1946]", "Mozilla/5.0")
    pkts.append((base + 2, eth(IPV6_CLIENT_MAC, IPV6_SERVER_MAC, 0x86DD) + ipv6(IPV6_CLIENT, IPV6_SERVER, 6, tcp(cport, dport, seq + 1, seq + 1, PSHACK, req.encode()))))
    resp = http_response(200, b"<html>ipv6</html>")
    pkts.append((base + 3, eth(IPV6_SERVER_MAC, IPV6_CLIENT_MAC, 0x86DD) + ipv6(IPV6_SERVER, IPV6_CLIENT, 6, tcp(dport, cport, seq + 1, seq + 1, PSHACK, resp))))
    return pkts


def generate(out_path):
    rng = random.Random(42)
    packets = []
    t = float(T0)
    packets += normal_web(t + 1)
    packets += beaconing(t + 60)
    packets += port_scan(t + 90)
    packets += dns_tunnel(t + 120, rng)
    packets += data_exfil(t + 160)
    packets += http_errors(t + 220)
    packets += ipv6_web(t + 260)
    packets.sort(key=lambda p: p[0])
    write_pcap(out_path, packets)
    return len(packets)


def main():
    parser = argparse.ArgumentParser(description="Generate a synthetic test PCAP")
    parser.add_argument("-o", "--out", default="tests/sample.pcap")
    args = parser.parse_args()
    n = generate(args.out)
    print("wrote %s with %d packets" % (args.out, n))


if __name__ == "__main__":
    main()
