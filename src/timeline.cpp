#include "timeline.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace {

std::string toLower(const std::string& s) {
    std::string out(s);
    for (auto& c : out) {
        c = (char)tolower((unsigned char)c);
    }
    return out;
}

// Returns true when the filter matches the host or the detail text.
bool matchesFilter(const std::string& host, const std::string& detail,
                   const std::string& filter) {
    if (filter.empty()) {
        return true;
    }
    std::string f = toLower(filter);
    if (toLower(host).find(f) != std::string::npos) {
        return true;
    }
    return toLower(detail).find(f) != std::string::npos;
}

bool inWindow(int64_t ts, int64_t sinceUs, int64_t untilUs) {
    if (sinceUs >= 0 && ts < sinceUs) {
        return false;
    }
    if (untilUs >= 0 && ts > untilUs) {
        return false;
    }
    return true;
}

void addSessionEntry(std::vector<TimelineEntry>& out, const ConversationRecord& c) {
    TimelineEntry e;
    e.timestampUs = c.startUs;
    e.captureId = c.captureId;
    e.host = c.srcIp;
    char buf[512];
    if (c.protocol == 6) {
        e.kind = "tcp_session";
        snprintf(buf, sizeof(buf), "%s:%u -> %s:%u [tcp] %llu packets, %llu payload bytes",
                 c.srcIp.c_str(), (unsigned)c.srcPort, c.dstIp.c_str(), (unsigned)c.dstPort,
                 (unsigned long long)c.packetCount, (unsigned long long)c.totalPayloadBytes);
    } else if (c.protocol == 17) {
        e.kind = "udp_flow";
        snprintf(buf, sizeof(buf), "%s:%u -> %s:%u [udp] %llu packets, %llu payload bytes",
                 c.srcIp.c_str(), (unsigned)c.srcPort, c.dstIp.c_str(), (unsigned)c.dstPort,
                 (unsigned long long)c.packetCount, (unsigned long long)c.totalPayloadBytes);
    } else {
        e.kind = "session";
        snprintf(buf, sizeof(buf), "%s:%u -> %s:%u [proto %d] %llu packets",
                 c.srcIp.c_str(), (unsigned)c.srcPort, c.dstIp.c_str(), (unsigned)c.dstPort,
                 c.protocol, (unsigned long long)c.packetCount);
    }
    e.detail = buf;
    out.push_back(e);
}

void addDnsEntry(std::vector<TimelineEntry>& out, const DnsQueryRecord& q) {
    TimelineEntry e;
    e.timestampUs = q.timestampUs;
    e.captureId = q.captureId;
    e.host = q.host;
    char buf[512];
    if (q.isResponse) {
        snprintf(buf, sizeof(buf), "%s %s response (rcode %d)", q.name.c_str(),
                 q.typeName.c_str(), q.rcode);
    } else {
        snprintf(buf, sizeof(buf), "%s %s", q.name.c_str(), q.typeName.c_str());
    }
    e.kind = q.isResponse ? "dns_response" : "dns_query";
    e.detail = buf;
    out.push_back(e);
}

void addHttpEntry(std::vector<TimelineEntry>& out, const HttpEventRecord& h) {
    TimelineEntry e;
    e.timestampUs = h.timestampUs;
    e.captureId = h.captureId;
    e.host = h.host;
    char buf[512];
    if (h.kind == "request") {
        e.kind = "http_request";
        if (!h.hostHeader.empty() && !h.userAgent.empty()) {
            snprintf(buf, sizeof(buf), "%s %s (Host: %s, UA: %s)",
                     h.method.c_str(), h.path.c_str(), h.hostHeader.c_str(),
                     h.userAgent.c_str());
        } else if (!h.hostHeader.empty()) {
            snprintf(buf, sizeof(buf), "%s %s (Host: %s)", h.method.c_str(),
                     h.path.c_str(), h.hostHeader.c_str());
        } else {
            snprintf(buf, sizeof(buf), "%s %s", h.method.c_str(), h.path.c_str());
        }
    } else {
        e.kind = "http_response";
        snprintf(buf, sizeof(buf), "HTTP/1.1 %d (server: %s, type: %s)", h.status,
                 h.server.c_str(), h.contentType.c_str());
    }
    e.detail = buf;
    out.push_back(e);
}

void addAnomalyEntry(std::vector<TimelineEntry>& out, const AnomalyRecord& a) {
    TimelineEntry e;
    e.timestampUs = a.firstDetectedUs > 0 ? a.firstDetectedUs : a.lastSeenUs;
    e.captureId = a.captureId;
    e.host = a.subject;
    char buf[512];
    snprintf(buf, sizeof(buf), "[%s] %s", a.severity.c_str(), a.evidence.c_str());
    e.kind = "anomaly";
    e.detail = buf;
    out.push_back(e);
}

}  // namespace

std::string formatTimestamp(int64_t tsUs) {
    time_t secs = (time_t)(tsUs / 1000000);
    struct tm tmv;
    struct tm* gm = gmtime(&secs);
    if (gm != nullptr) {
        tmv = *gm;
    } else {
        memset(&tmv, 0, sizeof(tmv));
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour,
             tmv.tm_min, tmv.tm_sec);
    return std::string(buf);
}

std::vector<TimelineEntry> buildTimeline(Storage& storage, int64_t sinceUs, int64_t untilUs,
                                         const std::string& hostFilter) {
    std::vector<TimelineEntry> out;
    std::vector<ConversationRecord> convs;
    std::string msg;
    if (!storage.listConversations("", "", 0, convs, msg)) {
        return out;
    }
    for (const ConversationRecord& c : convs) {
        addSessionEntry(out, c);
    }
    std::vector<DnsQueryRecord> dns;
    if (storage.listDnsQueries("", 0, dns, msg)) {
        for (const DnsQueryRecord& q : dns) {
            addDnsEntry(out, q);
        }
    }
    std::vector<HttpEventRecord> http;
    if (storage.listHttpEvents("", 0, http, msg)) {
        for (const HttpEventRecord& h : http) {
            addHttpEntry(out, h);
        }
    }
    std::vector<AnomalyRecord> anomalies;
    if (storage.listAnomalies(0, "", anomalies, msg)) {
        for (const AnomalyRecord& a : anomalies) {
            addAnomalyEntry(out, a);
        }
    }
    std::vector<TimelineEntry> filtered;
    for (const TimelineEntry& e : out) {
        if (!inWindow(e.timestampUs, sinceUs, untilUs)) {
            continue;
        }
        if (!matchesFilter(e.host, e.detail, hostFilter)) {
            continue;
        }
        filtered.push_back(e);
    }
    std::sort(filtered.begin(), filtered.end(), [](const TimelineEntry& a, const TimelineEntry& b) {
        if (a.timestampUs != b.timestampUs) {
            return a.timestampUs < b.timestampUs;
        }
        if (a.kind != b.kind) {
            return a.kind < b.kind;
        }
        return a.detail < b.detail;
    });
    return filtered;
}
