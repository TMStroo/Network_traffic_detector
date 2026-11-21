#include "detector.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cmath>
#include <cstdio>
#include <map>
#include <set>

namespace {

std::string formatDouble(double v, int prec) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%.*f", prec, v);
    return std::string(buf);
}

std::string describeConversation(const Conversation& c) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s:%u -> %s:%u", c.key.srcIp.c_str(),
             (unsigned)c.key.srcPort, c.key.dstIp.c_str(), (unsigned)c.key.dstPort);
    return std::string(buf);
}

struct LabelStats {
    double avg = 0;
    int max = 0;
};

// Computes average and maximum DNS label lengths of a name.
// Input: DNS name like "www.example.com".
// Output: LabelStats.
LabelStats labelStats(const std::string& name) {
    LabelStats out;
    int total = 0;
    int count = 0;
    int cur = 0;
    for (char ch : name) {
        if (ch == '.') {
            if (cur > 0) {
                total += cur;
                count++;
                if (cur > out.max) {
                    out.max = cur;
                }
            }
            cur = 0;
        } else {
            cur++;
        }
    }
    if (cur > 0) {
        total += cur;
        count++;
        if (cur > out.max) {
            out.max = cur;
        }
    }
    out.avg = count > 0 ? (double)total / count : 0;
    return out;
}

double medianOf(std::vector<double> v) {
    if (v.empty()) {
        return 0;
    }
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

double stddevOf(const std::vector<double>& v, double mean) {
    if (v.size() < 2) {
        return 0;
    }
    double sum = 0;
    for (double x : v) {
        sum += (x - mean) * (x - mean);
    }
    return std::sqrt(sum / (v.size() - 1));
}

// Returns the coefficient of variation of v: standard deviation over the mean.
double cvOf(const std::vector<double>& v) {
    if (v.empty()) {
        return 0;
    }
    double mean = 0;
    for (double x : v) {
        mean += x;
    }
    mean /= (double)v.size();
    return mean > 0 ? stddevOf(v, mean) / mean : 0;
}

// Parses a textual IP address.
// Input: IP text like "10.0.0.5" or "::1".
// Output: IpAddress; the address is invalid if the text is not a valid address.
IpAddress parseIpText(const std::string& s) {
    IpAddress a;
    if (inet_pton(AF_INET, s.c_str(), a.v4) == 1) {
        a.isIpv6 = false;
        return a;
    }
    if (inet_pton(AF_INET6, s.c_str(), a.v6) == 1) {
        a.isIpv6 = true;
        return a;
    }
    return a;
}

// Returns true for internal IPv4/IPv6 addresses (RFC1918, loopback, ULA).
// Input: IP text.
// Output: bool.
bool isInternalIp(const std::string& s) {
    IpAddress a = parseIpText(s);
    if (a.isIpv6) {
        bool isLoopback = true;
        for (int i = 0; i < 15; i++) {
            if (a.v6[i] != 0) {
                isLoopback = false;
                break;
            }
        }
        if (isLoopback && a.v6[15] == 1) {
            return true;
        }
        if ((a.v6[0] & 0xFE) == 0xFC) {
            return true;
        }
        return false;
    }
    if (a.v4[0] == 10) {
        return true;
    }
    if (a.v4[0] == 127) {
        return true;
    }
    if (a.v4[0] == 192 && a.v4[1] == 168) {
        return true;
    }
    if (a.v4[0] == 172 && a.v4[1] >= 16 && a.v4[1] <= 31) {
        return true;
    }
    return false;
}

// Returns true for the usual public service ports used by legitimate traffic.
// Input: port number.
// Output: bool.
bool isStandardPort(int port) {
    static const std::set<int> kStandardPorts = {
        80, 443, 53, 25, 465, 587, 993, 995, 22, 21, 110, 143, 3306, 5432, 1433,
        3389, 8443, 8080, 8888, 2052, 2082, 2083, 2086, 2087, 2095, 2096, 6379,
        27017};
    return kStandardPorts.count(port) != 0;
}

void setTimes(AnomalyRecord& r, int64_t first, int64_t last, int64_t count) {
    r.firstDetectedUs = first;
    r.lastSeenUs = last;
    r.eventCount = count;
}

// ---------------------------------------------------------------------------

// Detects hosts that send many DNS queries with long or random-looking names.
// Input: conversations to analyze.
// Output: appends dns_tunneling anomalies.
void detectDnsTunneling(const std::vector<Conversation>& convs, std::vector<AnomalyRecord>& out) {
    struct HostAgg {
        std::set<std::string> names;
        int queries = 0;
        int nxdomains = 0;
        int suspTypeQueries = 0;
        double avgLabelLen = 0;
        int maxLabelLen = 0;
        int64_t minT = 0;
        int64_t maxT = 0;
    };
    std::map<std::string, HostAgg> agg;
    for (const Conversation& c : convs) {
        if (c.dnsQueries.empty()) {
            continue;
        }
        for (const DnsQueryEvent& q : c.dnsQueries) {
            // Requests travel from client to resolver. Responses travel in
            // the opposite direction, so attribute both to the client host.
            std::string host = q.isResponse ? c.key.dstIp : c.key.srcIp;
            HostAgg& a = agg[host];
            if (q.isResponse) {
                if (q.rcode == 3) {
                    a.nxdomains++;
                }
                continue;
            }
            a.names.insert(q.name);
            a.queries++;
            if (q.qtype == 10 || q.qtype == 255 || q.qtype == 99 || q.qtype == 16 ||
                q.qtype == 64 || q.qtype == 65 || q.qtype == 33) {
                a.suspTypeQueries++;
            }
            LabelStats ls = labelStats(q.name);
            a.avgLabelLen += ls.avg;
            if (ls.max > a.maxLabelLen) {
                a.maxLabelLen = ls.max;
            }
            if (a.minT == 0 || q.timestampUs < a.minT) {
                a.minT = q.timestampUs;
            }
            if (q.timestampUs > a.maxT) {
                a.maxT = q.timestampUs;
            }
        }
    }
    for (auto& kv : agg) {
        HostAgg& a = kv.second;
        int uniqueNames = (int)a.names.size();
        if (a.queries > 0) {
            a.avgLabelLen /= a.queries;
        }
        // Require both repeated unique names and at least one unusually long
        // DNS label. This avoids alerting on ordinary high-volume DNS alone.
        if (a.queries < 12 || uniqueNames < 10 ||
            (a.maxLabelLen < 20 && a.avgLabelLen < 12.0)) {
            continue;
        }
        AnomalyRecord r;
        r.type = "dns_tunneling";
        r.severity = "high";
        r.subject = kv.first;
        r.evidence = "Host " + kv.first + " sent " + std::to_string(a.queries) +
                     " DNS queries with " + std::to_string(uniqueNames) +
                     " unique names, average label length " +
                     formatDouble(a.avgLabelLen, 1) + ", max label length " +
                     std::to_string(a.maxLabelLen) + ", NXDOMAIN responses " +
                     std::to_string(a.nxdomains) + ", suspicious type queries " +
                     std::to_string(a.suspTypeQueries) + ".";
        r.explanation = "DNS is used as a data carrier: a host sending a high volume of "
                        "unique DNS names, often with long or random-looking labels, is "
                        "suspected of tunneling data through the DNS hierarchy (for "
                        "example, data exfiltration or command traffic for malware). "
                        "Normal traffic produces few unique names with short labels; the "
                        "telltales here are the name volume and name shape.";
        r.confidence = std::min(0.9, 0.5 + 0.02 * (uniqueNames - 10));
        setTimes(r, a.minT, a.maxT, a.queries);
        out.push_back(r);
    }
}

// Detects hosts sending many DNS queries that end in NXDOMAIN.
// Input: conversations to analyze.
// Output: appends dns_high_nxdomain anomalies.
void detectDnsHighNxdomain(const std::vector<Conversation>& convs, std::vector<AnomalyRecord>& out) {
    struct HostAgg {
        int queries = 0;
        int nxdomains = 0;
        int64_t minT = 0;
        int64_t maxT = 0;
    };
    std::map<std::string, HostAgg> agg;
    for (const Conversation& c : convs) {
        if (c.dnsQueries.empty()) {
            continue;
        }
        for (const DnsQueryEvent& q : c.dnsQueries) {
            // Count requests and responses separately, under the client IP.
            std::string host = q.isResponse ? c.key.dstIp : c.key.srcIp;
            HostAgg& a = agg[host];
            if (q.isResponse) {
                if (q.rcode == 3) {
                    a.nxdomains++;
                }
            } else {
                a.queries++;
            }
            if (a.minT == 0 || q.timestampUs < a.minT) {
                a.minT = q.timestampUs;
            }
            if (q.timestampUs > a.maxT) {
                a.maxT = q.timestampUs;
            }
        }
    }
    for (auto& kv : agg) {
        HostAgg& a = kv.second;
        if (a.queries < 10 || a.nxdomains < 10) {
            continue;
        }
        double rate = (double)a.nxdomains / a.queries;
        if (rate < 0.5) {
            continue;
        }
        AnomalyRecord r;
        r.type = "dns_high_nxdomain";
        r.severity = "medium";
        r.subject = kv.first;
        r.evidence = "Host " + kv.first + " sent " + std::to_string(a.queries) +
                     " DNS queries with " + std::to_string(a.nxdomains) +
                     " NXDOMAIN responses (" + formatDouble(rate * 100, 1) + "% of queries).";
        r.explanation = "A high rate of DNS failures suggests the host is guessing "
                        "hostnames: the caller of resolve() or gethostbyname() is being "
                        "attacked, or internal naming changes break clients. High NXDOMAIN "
                        "traffic is worth checking against logs of failed logins or "
                        "recon probes.";
        r.confidence = std::min(0.85, 0.4 + 0.1 * rate);
        setTimes(r, a.minT, a.maxT, a.queries);
        out.push_back(r);
    }
}

// Detects source-destination host pairs that dial many different ports.
// Input: conversations to analyze.
// Output: appends port_scan anomalies.
void detectPortScan(const std::vector<Conversation>& convs, std::vector<AnomalyRecord>& out) {
    std::map<std::pair<std::string, std::string>,
             std::vector<std::pair<int64_t, int>>>
        scans;
    for (const Conversation& c : convs) {
        if (c.key.srcPort == 0 || c.key.dstPort == 0) {
            continue;
        }
        scans[{c.key.srcIp, c.key.dstIp}].push_back({c.firstPacketUs, c.key.dstPort});
    }
    for (auto& kv : scans) {
        auto& v = kv.second;
        std::sort(v.begin(), v.end());
        std::set<int> ports;
        for (const auto& e : v) {
            ports.insert(e.second);
        }
        if (ports.size() < 8) {
            continue;
        }
        int64_t spanUs = v.back().first - v.front().first;
        if (spanUs > 30LL * 1000 * 1000) {
            continue;  // keep the alert on bursts, not steady dribbles
        }
        std::string portList;
        int shown = 0;
        for (int p : ports) {
            if (shown++ >= 8) {
                break;
            }
            if (!portList.empty()) {
                portList += ", ";
            }
            portList += std::to_string(p);
        }
        AnomalyRecord r;
        r.type = "port_scan";
        r.severity = "high";
        r.subject = kv.first.first + " -> " + kv.first.second;
        r.evidence = kv.first.first + " contacted " + std::to_string(ports.size()) +
                     " distinct destination ports (first 8: " + portList + ") from " +
                     kv.first.second + " within " + formatDouble(spanUs / 1e6, 1) +
                     " seconds.";
        r.explanation = "A single source probing many ports on one host is classic "
                        "port scanning or service discovery. Legitimate traffic "
                        "rarely opens more than a handful of ports on one peer in a "
                        "short window. Check whether the host is alive or has a "
                        "half-open TCP state from the burst.";
        r.confidence = std::min(0.85, 0.4 + 0.07 * ports.size());
        setTimes(r, v.front().first, v.back().first, (int64_t)v.size());
        out.push_back(r);
    }
}

// Detects conversations with periodic, regular activity.
// Input: conversations to analyze.
// Output: appends beaconing anomalies.
void detectBeaconing(const std::vector<Conversation>& convs, std::vector<AnomalyRecord>& out) {
    for (const Conversation& c : convs) {
        if (c.eventTimes.size() < 8) {
            continue;
        }
        std::vector<double> iv;
        for (size_t i = 1; i < c.eventTimes.size(); i++) {
            iv.push_back((double)(c.eventTimes[i] - c.eventTimes[i - 1]) / 1e6);
        }
        double med = medianOf(iv);
        if (med < 10.0) {
            continue;
        }
        double cv = cvOf(iv);
        if (med > 3600.0 || cv > 0.35) {
            continue;
        }
        AnomalyRecord r;
        r.type = "beaconing";
        r.severity = "high";
        r.subject = describeConversation(c);
        r.evidence = "Events every " + formatDouble(med, 1) + "s on average with a "
                     "regularity of " + formatDouble(cv * 100, 1) + "% (" +
                     std::to_string(iv.size()) + " intervals, median " +
                     formatDouble(med, 1) + "s).";
        r.explanation = "The same hosts exchange traffic at a steady cadence, which is "
                        "consistent with command-and-control beaconing: malware on the "
                        "source host regularly calls home. Normal traffic has bursty, "
                        "irregular intervals, so low spread over minutes or hours is the "
                        "telltale. Confirm by correlating the source with other alerts "
                        "or by inspecting the source host.";
        r.confidence = std::min(0.85, 0.5 + 0.3 * (0.35 - cv) / 0.35);
        setTimes(r, c.firstPacketUs, c.lastPacketUs, (int64_t)c.eventTimes.size());
        out.push_back(r);
    }
}

// Detects large internal-to-external transfers.
// Input: conversations to analyze.
// Output: appends data_exfil anomalies.
void detectDataExfil(const std::vector<Conversation>& convs, std::vector<AnomalyRecord>& out) {
    for (const Conversation& c : convs) {
        if (c.totalBytes == 0 || c.totalPayloadBytes == 0) {
            continue;
        }
        double ratio = (double)c.totalPayloadBytes / (double)c.totalBytes;
        bool internalToExternal =
            isInternalIp(c.key.srcIp) && !isInternalIp(c.key.dstIp);
        bool unusualPort =
            !isStandardPort(c.key.srcPort) && !isStandardPort(c.key.dstPort);
        if (c.totalPayloadBytes < 50000) {
            continue;
        }
        if (internalToExternal) {
            AnomalyRecord r;
            r.type = "data_exfil";
            r.severity = "medium";
            r.subject = describeConversation(c);
            r.evidence = "Internal host " + c.key.srcIp + " sent " +
                         std::to_string(c.totalPayloadBytes) + " payload bytes (" +
                         formatDouble(ratio * 100, 1) + "% of the conversation) to " +
                         c.key.dstIp + " (port " + std::to_string(c.key.dstPort) + ").";
            r.explanation = "An internal host moved a large volume of data to an "
                            "external address. Legitimate uploads happen, but combined "
                            "with unusual ports or hosts never seen before, this fits "
                            "data exfiltration: check the data receiver and any logs of "
                            "who should talk to what host.";
            r.confidence = 0.65;
            setTimes(r, c.firstPacketUs, c.lastPacketUs, (int64_t)c.packetCount);
            out.push_back(r);
        } else if (unusualPort) {
            AnomalyRecord r;
            r.type = "data_exfil";
            r.severity = "medium";
            r.subject = describeConversation(c);
            r.evidence = std::to_string(c.totalPayloadBytes) + " payload bytes on " +
                         "uncommon ports (" + std::to_string(c.key.srcPort) + " -> " +
                         std::to_string(c.key.dstPort) + ") between " + c.key.srcIp +
                         " and " + c.key.dstIp + ".";
            r.explanation = "Traffic on uncommon ports carrying a large amount of data "
                            "is suspicious: legitimate services mostly use known ports "
                            "(web 80/443, DNS 53, SSH 22, mail 25/587). Unknown services "
                            "on unusual ports may be hidden exfiltration channels.";
            r.confidence = 0.55;
            setTimes(r, c.firstPacketUs, c.lastPacketUs, (int64_t)c.packetCount);
            out.push_back(r);
        }
    }
}

// Detects HTTP conversations with many client or server errors.
// Input: conversations to analyze.
// Output: appends http_errors anomalies.
void detectHttpErrors(const std::vector<Conversation>& convs, std::vector<AnomalyRecord>& out) {
    for (const Conversation& c : convs) {
        int bad = c.http.status404 + c.http.status5xx;
        if (bad < 3) {
            continue;
        }
        AnomalyRecord r;
        r.type = "http_errors";
        r.severity = "low";
        r.subject = describeConversation(c);
        r.evidence = describeConversation(c) + ": " + std::to_string(c.http.status404) +
                     " responses with status 404 and " + std::to_string(c.http.status5xx) +
                     " with status 5xx.";
        r.explanation = "Several failed HTTP responses from one host pair are unusual "
                        "for normal web browsing: a burst of 404s or 5xx responses may "
                        "mean a probing tool, a broken deployment, or a scanner. A few "
                        "errors are normal; a burst is worth a look.";
        r.confidence = std::min(0.7, 0.35 + 0.05 * bad);
        setTimes(r, c.firstPacketUs, c.lastPacketUs, (int64_t)(c.http.status404 + c.http.status5xx));
        out.push_back(r);
    }
}

// Detects TCP or non-standard protocols on ports outside the usual service set.
// Input: conversations to analyze.
// Output: appends unusual_protocol_port anomalies.
void detectUnusualProtocolPort(const std::vector<Conversation>& convs,
                               std::vector<AnomalyRecord>& out) {
    for (const Conversation& c : convs) {
        bool isStandardProto = c.key.protocol == 6 || c.key.protocol == 17 ||
                               c.key.protocol == 1 || c.key.protocol == 41 ||
                               c.key.protocol == 58;
        if (isStandardProto) {
            continue;
        }
        if (isStandardPort(c.key.srcPort) || isStandardPort(c.key.dstPort)) {
            continue;
        }
        if (c.totalBytes < 200) {
            continue;
        }
        AnomalyRecord r;
        r.type = "unusual_protocol_port";
        r.severity = "medium";
        r.subject = describeConversation(c);
        r.evidence = describeConversation(c) + " uses protocol " +
                     std::to_string(c.key.protocol) + " on uncommon ports (" +
                     std::to_string(c.key.srcPort) + " -> " + std::to_string(c.key.dstPort) +
                     ") with " + std::to_string(c.totalBytes) + " bytes.";
        r.explanation = "A non-TCP, non-UDP, non-ICMP protocol on uncommon ports is "
                        "suspicious: it may be encrypted or proprietary traffic worth "
                        "identifying, or a sign of hidden activity.";
        r.confidence = 0.6;
        setTimes(r, c.firstPacketUs, c.lastPacketUs, (int64_t)c.packetCount);
        out.push_back(r);
    }
}

}  // namespace

// Detects unusual communication patterns across all conversations.
// Input: conversations to analyze (already rebuilt by ConversationTracker).
// Output: anomalies with type, severity, subject, evidence, explanation,
//         confidence and event counts.
std::vector<AnomalyRecord> detectAnomalies(const std::vector<Conversation>& convs) {
    std::vector<AnomalyRecord> out;
    detectDnsTunneling(convs, out);
    detectDnsHighNxdomain(convs, out);
    detectPortScan(convs, out);
    detectBeaconing(convs, out);
    detectDataExfil(convs, out);
    detectHttpErrors(convs, out);
    detectUnusualProtocolPort(convs, out);
    return out;
}
