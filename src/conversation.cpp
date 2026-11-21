#include "conversation.h"

#include <algorithm>
#include <set>

namespace {

bool isSignificant(const PacketMetadata& p) {
    if (p.tcpDataLength > 0 || p.hasDns) {
        return true;
    }
    if (p.hasUdp && !p.udpPayload.empty()) {
        return true;
    }
    if (p.syn || p.fin || p.rst) {
        return true;
    }
    return false;
}

std::string joinStrings(const std::vector<std::string>& in) {
    std::string out;
    for (const auto& v : in) {
        if (v.empty()) {
            continue;
        }
        if (!out.empty()) {
            out += ", ";
        }
        out += v;
    }
    return out;
}

// Joins unique values from a vector, preserving order of first appearance.
std::string joinUnique(const std::vector<std::string>& in) {
    std::vector<std::string> seen;
    for (const auto& v : in) {
        if (!v.empty() && std::find(seen.begin(), seen.end(), v) == seen.end()) {
            seen.push_back(v);
        }
    }
    return joinStrings(seen);
}

}  // namespace

void ConversationTracker::FlowState::addSegment(uint32_t seq, const std::string& data) {
    if (!data.empty()) {
        pending.push_back(std::make_pair(seq, data));
    }
    std::sort(pending.begin(), pending.end(),
              [](const std::pair<uint32_t, std::string>& a,
                 const std::pair<uint32_t, std::string>& b) {
                  return a.first < b.first;
              });
    if (!hasExpected) {
        if (pending.empty()) {
            return;
        }
        expectedSeq = pending[0].first;
        hasExpected = true;
    }
    size_t i = 0;
    while (i < pending.size()) {
        uint32_t segSeq = pending[i].first;
        const std::string& segData = pending[i].second;
        if (segSeq > expectedSeq) {
            break;  // gap: wait for the missing segment
        }
        size_t skip = (size_t)(expectedSeq - segSeq);
        if (skip < segData.size()) {
            stream.append(segData.data() + skip, segData.size() - skip);
        }
        expectedSeq = std::max(expectedSeq, segSeq + (uint32_t)segData.size());
        i++;
    }
    if (i > 0) {
        pending.erase(pending.begin(), pending.begin() + (long)i);
    }
    if (pending.size() > 4096) {
        pending.clear();  // safety cap for pathological captures
    }
}

ConversationKey ConversationTracker::keyOf(const PacketMetadata& p) const {
    ConversationKey k;
    k.srcIp = p.srcIp.text();
    k.dstIp = p.dstIp.text();
    if (p.hasTcp) {
        k.srcPort = p.tcpSrcPort;
        k.dstPort = p.tcpDstPort;
        k.protocol = 6;
    } else if (p.hasUdp) {
        k.srcPort = p.udpSrcPort;
        k.dstPort = p.udpDstPort;
        k.protocol = 17;
    } else {
        k.protocol = p.ipProtocol;
    }
    return k;
}

void ConversationTracker::addPacket(const PacketMetadata& p) {
    if (!p.hasIp) {
        return;
    }
    ConversationKey k = keyOf(p);
    Conversation& c = convs_[k];
    if (c.key.srcIp.empty()) {
        c.key = k;
    }
    if (c.firstPacketUs == 0) {
        c.firstPacketUs = p.timestampUs;
    }
    c.lastPacketUs = p.timestampUs;
    c.packetCount++;
    c.totalBytes += (uint64_t)(p.ipTotalLength > 0 ? p.ipTotalLength : p.frameLength);
    if (p.hasTcp) {
        c.totalPayloadBytes += (uint64_t)p.tcpDataLength;
        if (p.syn && c.synTimeUs < 0) {
            c.synTimeUs = p.timestampUs;
        }
        if (p.rst) {
            c.sawRst = true;
        }
        if (p.tcpDataLength > 0) {
            flows_[k].addSegment(p.tcpSeq, p.tcpPayload);
        }
    } else if (p.hasUdp) {
        c.totalPayloadBytes += (uint64_t)p.udpPayload.size();
        if (!p.udpPayload.empty()) {
            c.stream += p.udpPayload;
        }
    }
    if (p.hasEthernet) {
        hostMacs[p.srcIp.text()] = p.srcMac;
        hostMacs[p.dstIp.text()] = p.dstMac;
    }
    if (p.hasDns) {
        c.hasDns = true;
        DnsQueryEvent ev;
        ev.timestampUs = p.timestampUs;
        ev.name = p.dnsQueryName;
        ev.qtype = p.dnsQueryType;
        ev.typeName = p.dnsQueryTypeName;
        ev.isResponse = p.dnsIsResponse;
        ev.rcode = p.dnsRcode;
        for (const DnsAnswer& a : p.dnsAnswers) {
            ev.answers.insert(ev.answers.end(), a.ips.begin(), a.ips.end());
            ev.answers.insert(ev.answers.end(), a.values.begin(), a.values.end());
        }
        c.dnsQueries.push_back(ev);
    }
    if (isSignificant(p)) {
        c.eventTimes.push_back(p.timestampUs);
    }
}

std::vector<Conversation> ConversationTracker::finish() {
    std::vector<Conversation> out;
    out.reserve(convs_.size());
    for (auto& kv : convs_) {
        Conversation& c = kv.second;
        auto it = flows_.find(kv.first);
        if (it != flows_.end()) {
            c.stream = it->second.stream;
        }
        if (c.key.srcIp.empty()) {
            c.key = kv.first;
        }
        c.http = parseHttpMessages(c.stream);
        out.push_back(c);
    }
    std::sort(out.begin(), out.end(), [](const Conversation& a, const Conversation& b) {
        return a.firstPacketUs < b.firstPacketUs;
    });
    return out;
}

std::vector<HostRecord> aggregateHosts(const std::vector<Conversation>& convs,
                                       const std::map<std::string, MacAddress>& hostMacs) {
    std::map<std::string, HostRecord> agg;
    for (const Conversation& c : convs) {
        HostRecord& src = agg[c.key.srcIp];
        if (src.ip.empty()) {
            src.ip = c.key.srcIp;
        }
        auto mit = hostMacs.find(c.key.srcIp);
        if (mit != hostMacs.end() && src.mac.empty()) {
            src.mac = mit->second.text();
        }
        if (src.firstSeenUs == 0 || c.firstPacketUs < src.firstSeenUs) {
            src.firstSeenUs = c.firstPacketUs;
        }
        if (c.lastPacketUs > src.lastSeenUs) {
            src.lastSeenUs = c.lastPacketUs;
        }
        src.packetCount += c.packetCount;
        src.bytesSent += c.totalPayloadBytes;

        HostRecord& dst = agg[c.key.dstIp];
        if (dst.ip.empty()) {
            dst.ip = c.key.dstIp;
        }
        auto dit = hostMacs.find(c.key.dstIp);
        if (dit != hostMacs.end() && dst.mac.empty()) {
            dst.mac = dit->second.text();
        }
        if (dst.firstSeenUs == 0 || c.firstPacketUs < dst.firstSeenUs) {
            dst.firstSeenUs = c.firstPacketUs;
        }
        if (c.lastPacketUs > dst.lastSeenUs) {
            dst.lastSeenUs = c.lastPacketUs;
        }
        dst.packetCount += c.packetCount;
        dst.bytesReceived += c.totalPayloadBytes;
    }
    std::vector<HostRecord> out;
    out.reserve(agg.size());
    for (auto& kv : agg) {
        out.push_back(kv.second);
    }
    return out;
}

ConversationRecord toConversationRecord(const Conversation& conv,
                                        int64_t captureId,
                                        int64_t srcHostId,
                                        int64_t dstHostId) {
    ConversationRecord r;
    r.srcIp = conv.key.srcIp;
    r.srcPort = conv.key.srcPort;
    r.dstIp = conv.key.dstIp;
    r.dstPort = conv.key.dstPort;
    r.protocol = conv.key.protocol;
    r.srcHostId = srcHostId;
    r.dstHostId = dstHostId;
    r.captureId = captureId;
    r.startUs = conv.firstPacketUs;
    r.endUs = conv.lastPacketUs;
    r.packetCount = conv.packetCount;
    r.totalBytes = conv.totalBytes;
    r.totalPayloadBytes = conv.totalPayloadBytes;
    r.isDns = conv.hasDns;
    if (!conv.dnsQueries.empty()) {
        r.dnsQueryName = conv.dnsQueries[0].name;
        r.dnsQueryType = conv.dnsQueries[0].qtype;
        r.dnsQueryTypeName = conv.dnsQueries[0].typeName;
    }
    r.isHttp = !conv.http.requests.empty() || !conv.http.responses.empty();
    r.httpRequests = (int)conv.http.requests.size();
    r.httpResponses = (int)conv.http.responses.size();
    r.status404 = conv.http.status404;
    r.status5xx = conv.http.status5xx;
    r.httpMethods = joinUnique([&conv]() {
        std::vector<std::string> v;
        for (const auto& r : conv.http.requests) {
            v.push_back(r.method);
        }
        return v;
    }());
    r.httpPaths = joinUnique([&conv]() {
        std::vector<std::string> v;
        for (const auto& r : conv.http.requests) {
            v.push_back(r.target);
        }
        return v;
    }());
    r.httpUserAgents = joinUnique([&conv]() {
        std::vector<std::string> v;
        for (const auto& r : conv.http.requests) {
            v.push_back(r.userAgent);
        }
        return v;
    }());
    r.httpHostHeaders = joinUnique([&conv]() {
        std::vector<std::string> v;
        for (const auto& r : conv.http.requests) {
            v.push_back(r.hostHeader);
        }
        return v;
    }());
    return r;
}
