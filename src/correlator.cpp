#include "correlator.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>

namespace {

// Describes a conversation five-tuple as text.
// Input: conversation record.
// Output: string like "10.0.0.2:1234 -> 203.0.113.5:443".
std::string describePair(const ConversationRecord& c) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s:%u -> %s:%u", c.srcIp.c_str(), (unsigned)c.srcPort,
             c.dstIp.c_str(), (unsigned)c.dstPort);
    return std::string(buf);
}

}  // namespace

std::vector<std::string> buildCorrelationReport(Storage& storage) {
    std::vector<std::string> lines;
    std::string msg;

    std::map<int64_t, std::string> capturePaths;
    {
        std::vector<CaptureRecord> caps;
        if (storage.listCaptures(caps, msg)) {
            for (const CaptureRecord& c : caps) {
                capturePaths[c.id] = c.path;
            }
        }
    }

    // Per host: which captures saw it, and total activity.
    struct HostAgg {
        std::set<int64_t> captures;
        int64_t packets = 0;
        int64_t payload = 0;
        int anomalies = 0;
    };
    std::map<std::string, HostAgg> hosts;

    std::vector<ConversationRecord> convs;
    if (!storage.listConversations("", "", 0, convs, msg)) {
        return lines;
    }
    for (const ConversationRecord& c : convs) {
        HostAgg& src = hosts[c.srcIp];
        src.captures.insert(c.captureId);
        src.packets += c.packetCount;
        src.payload += c.totalPayloadBytes;
        HostAgg& dst = hosts[c.dstIp];
        dst.captures.insert(c.captureId);
        dst.packets += c.packetCount;
        dst.payload += c.totalPayloadBytes;
    }

    std::vector<AnomalyRecord> anomalies;
    storage.listAnomalies(0, "", anomalies, msg);
    for (const AnomalyRecord& a : anomalies) {
        HostAgg& h = hosts[a.subject];
        h.anomalies++;
    }

    // Group anomalies by subject so each host anomaly is counted once.
    struct MultiHost {
        std::string ip;
        int captureCount = 0;
        int64_t packets = 0;
        int64_t payload = 0;
        int anomalies = 0;
    };
    std::vector<MultiHost> multi;
    for (auto& kv : hosts) {
        if (kv.second.captures.size() >= 2) {
            MultiHost m;
            m.ip = kv.first;
            m.captureCount = (int)kv.second.captures.size();
            m.packets = kv.second.packets;
            m.payload = kv.second.payload;
            m.anomalies = kv.second.anomalies;
            multi.push_back(m);
        }
    }
    std::sort(multi.begin(), multi.end(), [](const MultiHost& a, const MultiHost& b) {
        if (a.captureCount != b.captureCount) {
            return a.captureCount > b.captureCount;
        }
        return a.packets > b.packets;
    });

    // Conversation pairs repeated across captures.
    struct PairAgg {
        std::string pair;
        int protocol = 0;
        int count = 0;
        std::set<int64_t> captures;
        int64_t firstSeen = 0;
        int64_t lastSeen = 0;
    };
    std::map<std::string, PairAgg> pairs;
    for (const ConversationRecord& c : convs) {
        PairAgg& p = pairs[describePair(c) + " proto" + std::to_string(c.protocol)];
        p.pair = describePair(c);
        p.protocol = c.protocol;
        p.count++;
        p.captures.insert(c.captureId);
        if (p.firstSeen == 0 || c.startUs < p.firstSeen) {
            p.firstSeen = c.startUs;
        }
        if (c.endUs > p.lastSeen) {
            p.lastSeen = c.endUs;
        }
    }
    std::vector<PairAgg> pairList;
    for (auto& kv : pairs) {
        pairList.push_back(kv.second);
    }
    std::sort(pairList.begin(), pairList.end(), [](const PairAgg& a, const PairAgg& b) {
        if (a.count != b.count) {
            return a.count > b.count;
        }
        return a.pair < b.pair;
    });

    // Build the report text.
    lines.push_back("Hosts seen in multiple captures:");
    if (multi.empty()) {
        lines.push_back("  (none)");
    }
    for (const MultiHost& m : multi) {
        // Look up path names from the capture id set.
        std::string paths;
        for (int64_t cid : hosts[m.ip].captures) {
            auto it = capturePaths.find(cid);
            if (!paths.empty()) {
                paths += ", ";
            }
            paths += it != capturePaths.end() ? it->second : ("#" + std::to_string(cid));
        }
        char buf[512];
        snprintf(buf, sizeof(buf), "  %s: %d captures, %lld packets, %lld payload bytes, %d anomalies (captures: %s)",
                 m.ip.c_str(), m.captureCount, (long long)m.packets,
                 (long long)m.payload, m.anomalies, paths.c_str());
        lines.push_back(buf);
    }
    lines.push_back("");
    lines.push_back("Conversation pairs repeated across captures:");
    if (pairList.empty()) {
        lines.push_back("  (none)");
    }
    for (const PairAgg& p : pairList) {
        if (p.count < 2) {
            break;
        }
        char buf[512];
        snprintf(buf, sizeof(buf), "  %s [proto %d]: %d conversations across %d captures",
                 p.pair.c_str(), p.protocol, p.count, (int)p.captures.size());
        lines.push_back(buf);
    }
    return lines;
}
