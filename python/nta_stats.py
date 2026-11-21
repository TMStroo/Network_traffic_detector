#!/usr/bin/env python3
"""Statistical analysis module for NetworkTrafficAnalyzer.

Reads the SQLite database produced by `nta analyze` and prints a JSON report
with capture summaries, host and conversation statistics, anomaly
distributions and cross-capture activity distributions.

Usage: python3 nta_stats.py --db PATH
"""

import argparse
import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone

PROTO_NAME = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    41: "ipv6",
    58: "icmpv6",
    132: "sctp",
}


def _fmt_us(ts_us):
    """Formats a microsecond timestamp for display.

    Input: microseconds since the Unix epoch (0 means unknown).
    Output: ISO 8601 string in UTC, or an empty string.
    """
    if not ts_us:
        return ""
    return datetime.fromtimestamp(ts_us / 1000000, tz=timezone.utc).isoformat(
        timespec="seconds"
    )


def _load(conn, sql):
    return conn.execute(sql).fetchall()


def analyze_captures(conn):
    """Builds per-capture summaries: sizes, durations, rates, activity spread."""
    rows = _load(
        conn,
        """
        SELECT id, path, fileSize, packets, bytes, firstPacketUs, lastPacketUs
        FROM captures ORDER BY firstPacketUs
        """,
    )
    out = []
    for cid, path, size, packets, nbytes, first, last in rows:
        duration = (last - first) / 1000000 if last > first else 0.0
        out.append(
            {
                "id": cid,
                "file": path,
                "fileSizeBytes": size,
                "packets": packets,
                "bytes": nbytes,
                "durationSeconds": round(duration, 3),
                "bytesPerSecond": round(nbytes / duration, 1) if duration > 0 else 0.0,
                "packetRatePerSecond": round(packets / duration, 1)
                if duration > 0
                else 0.0,
                "avgIntervalSeconds": round(duration / packets, 6) if packets else 0.0,
                "firstPacketUtc": _fmt_us(first),
                "lastPacketUtc": _fmt_us(last),
            }
        )
    return out


def analyze_hosts(conn):
    """Builds per-host summaries: packet and byte volumes, activity rates."""
    rows = _load(
        conn,
        """
        SELECT id, ip, mac, firstSeenUs, lastSeenUs, packetCount, bytesSent, bytesReceived
        FROM hosts ORDER BY packetCount DESC
        """,
    )
    out = []
    for hid, ip, mac, first, last, packets, sent, recv in rows:
        span = (last - first) / 1000000 if last > first else 0.0
        out.append(
            {
                "id": hid,
                "ip": ip,
                "mac": mac,
                "packetCount": packets,
                "bytesSent": sent,
                "bytesReceived": recv,
                "packetsPerSecond": round(packets / span, 1) if span > 0 else 0.0,
                "firstSeenUtc": _fmt_us(first),
                "lastSeenUtc": _fmt_us(last),
            }
        )
    return out


def analyze_conversations(conn):
    """Summarizes conversations: distribution by protocol and by size."""
    rows = _load(
        conn,
        """
        SELECT protocol, packetCount, totalPayloadBytes
        FROM conversations
        """,
    )
    proto_counts = Counter()
    payloads = []
    packets = []
    for proto, pkts, payload in rows:
        proto_counts[PROTO_NAME.get(proto, str(proto))] += 1
        payloads.append(payload or 0)
        packets.append(pkts or 0)
    largest = sorted(payloads, reverse=True)[:5]
    return {
        "total": len(rows),
        "byProtocol": dict(proto_counts.most_common()),
        "avgPayloadPerConversationBytes": round(sum(payloads) / len(payloads), 1)
        if payloads
        else 0.0,
        "avgPacketsPerConversation": round(sum(packets) / len(packets), 1)
        if packets
        else 0.0,
        "largestPayloadBytes": largest,
    }


def analyze_anomalies(conn):
    """Summarizes detected anomalies: counts by type and severity, confidence."""
    rows = _load(
        conn,
        """
        SELECT type, severity, confidence, captureId FROM anomalies
        """,
    )
    by_type = Counter()
    by_sev = Counter()
    confs = []
    per_capture = Counter()
    for typ, sev, conf, cap in rows:
        by_type[typ] += 1
        by_sev[sev] += 1
        confs.append(conf or 0.0)
        if cap:
            per_capture[cap] += 1
    return {
        "total": len(rows),
        "byType": dict(by_type.most_common()),
        "bySeverity": dict(by_sev.most_common()),
        "meanConfidence": round(sum(confs) / len(confs), 3) if confs else 0.0,
        "perCapture": {str(k): v for k, v in sorted(per_capture.items())},
    }


def analyze_activity(conn):
    """Counts packets per UTC hour and per UTC day from the packet log."""
    by_hour = Counter()
    by_day = Counter()
    total_bytes = 0
    for ts, nbytes in _load(conn, "SELECT timestampUs, bytes FROM packets"):
        if ts <= 0:
            continue
        dt = datetime.fromtimestamp(ts / 1000000, tz=timezone.utc)
        by_hour[dt.strftime("%Y-%m-%d %H")] += 1
        by_day[dt.strftime("%Y-%m-%d")] += 1
        total_bytes += nbytes or 0
    return {
        "packetCount": sum(by_hour.values()),
        "bytesTotal": total_bytes,
        "byHourUTC": dict(sorted(by_hour.items())),
        "byDayUTC": dict(sorted(by_day.items())),
    }


def analyze_cross_capture(conn):
    """Lists hosts seen in multiple captures, with packet counts per capture."""
    rows = _load(
        conn,
        """
        SELECT host, COUNT(DISTINCT captureId) AS captureCount, SUM(packetCount) AS packets
        FROM (
            SELECT srcIp AS host, captureId, COUNT(*) AS packetCount FROM packets GROUP BY srcIp, captureId
            UNION ALL
            SELECT dstIp AS host, captureId, COUNT(*) AS packetCount FROM packets GROUP BY dstIp, captureId
        )
        GROUP BY host
        HAVING captureCount >= 2
        ORDER BY captureCount DESC, packets DESC
        """,
    )
    return [
        {"host": host, "captureCount": capcount, "packets": packets or 0}
        for host, capcount, packets in rows
    ]


def main():
    parser = argparse.ArgumentParser(
        description="Statistical analysis module for NetworkTrafficAnalyzer"
    )
    parser.add_argument("--db", required=True, help="path to the analysis database")
    args = parser.parse_args()

    conn = sqlite3.connect("file:%s?mode=ro" % args.db, uri=True)
    try:
        report = {
            "captures": analyze_captures(conn),
            "hosts": analyze_hosts(conn),
            "conversations": analyze_conversations(conn),
            "anomalies": analyze_anomalies(conn),
            "activity": analyze_activity(conn),
            "crossCaptureHosts": analyze_cross_capture(conn),
        }
        print(json.dumps(report, indent=2, sort_keys=True))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
