#include "packet.h"

#include <arpa/inet.h>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

uint16_t readU16(const uint8_t* p, bool bigEndian) {
    if (bigEndian) {
        return (uint16_t)((p[0] << 8) | p[1]);
    }
    return (uint16_t)(p[0] | (p[1] << 8));
}

uint32_t readU32(const uint8_t* p, bool bigEndian) {
    if (bigEndian) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

std::string v4ToText(const uint8_t* p) {
    char buf[64];
    if (inet_ntop(AF_INET, p, buf, sizeof(buf)) == nullptr) {
        return "0.0.0.0";
    }
    return std::string(buf);
}

std::string v6ToText(const uint8_t* p) {
    char buf[64];
    if (inet_ntop(AF_INET6, p, buf, sizeof(buf)) == nullptr) {
        return "::";
    }
    return std::string(buf);
}

// Parses a DNS name starting at *pos, following compression pointers.
// Input: buffer, buffer length, pointer to current offset.
// Output: name string; *pos advanced past the name (after the first pointer or
// the terminating zero byte). Returns false when the name is malformed.
bool readDnsName(const uint8_t* buf, size_t len, size_t* pos, std::string& out) {
    size_t p = *pos;
    size_t end = std::string::npos;
    int jumps = 0;
    out.clear();
    while (p < len) {
        uint8_t b = buf[p];
        if ((b & 0xC0) == 0xC0) {
            if (p + 2 > len) {
                return false;
            }
            uint16_t ptr = (uint16_t)(((b & 0x3F) << 8) | buf[p + 1]);
            if (ptr >= len) {
                return false;
            }
            if (end == std::string::npos) {
                end = p + 2;
            }
            if (++jumps > 16) {
                return false;
            }
            p = ptr;
            continue;
        }
        if (b == 0) {
            if (end == std::string::npos) {
                end = p + 1;
            }
            break;
        }
        if (p + 1 + b > len) {
            return false;
        }
        if (!out.empty()) {
            out += '.';
        }
        for (int i = 0; i < b; i++) {
            char ch = (char)buf[p + 1 + i];
            out += (ch >= 32 && ch < 127) ? ch : '?';
        }
        p += 1 + b;
    }
    if (end == std::string::npos) {
        return false;
    }
    *pos = end;
    return true;
}

const char* dnsTypeName(int type) {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 3: return "MD";
        case 4: return "MF";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 7: return "MB";
        case 8: return "MG";
        case 9: return "MR";
        case 10: return "NULL";
        case 12: return "PTR";
        case 13: return "HINFO";
        case 15: return "MX";
        case 16: return "TXT";
        case 17: return "RP";
        case 18: return "AFSDB";
        case 19: return "X25";
        case 20: return "ISDN";
        case 21: return "RT";
        case 22: return "NSAP";
        case 25: return "SIG";
        case 28: return "AAAA";
        case 29: return "LOC";
        case 33: return "SRV";
        case 35: return "NAPTR";
        case 36: return "KX";
        case 37: return "CERT";
        case 39: return "DNAME";
        case 41: return "OPT";
        case 43: return "DS";
        case 45: return "A6";
        case 46: return "RRSIG";
        case 47: return "NSEC";
        case 48: return "DNSKEY";
        case 50: return "NSEC3";
        case 55: return "HIP";
        case 59: return "CDS";
        case 60: return "CDNSKEY";
        case 62: return "CSYNC";
        case 63: return "ZONEMD";
        case 64: return "SVCB";
        case 65: return "HTTPS";
        case 99: return "SPF";
        case 108: return "EUI48";
        case 109: return "EUI64";
        case 249: return "TKEY";
        case 250: return "TSIG";
        case 255: return "ANY";
        default: return "TYPE";
    }
}

void parseDnsMessage(const uint8_t* buf, size_t len, PacketMetadata& m) {
    m.hasDns = true;
    if (len < 12) {
        return;
    }
    size_t p = 12;
    uint16_t flags = readU16(buf + 2, true);
    uint16_t qd = readU16(buf + 4, true);
    uint16_t an = readU16(buf + 6, true);
    uint16_t ns = readU16(buf + 8, true);
    uint16_t ar = readU16(buf + 10, true);
    m.dnsIsResponse = (flags & 0x8000) != 0;
    m.dnsRcode = flags & 0x000F;
    m.dnsTruncated = (flags & 0x0200) != 0;
    m.dnsRecursionAvailable = (flags & 0x0080) != 0;

    for (int i = 0; i < qd; i++) {
        std::string name;
        if (!readDnsName(buf, len, &p, name)) {
            return;
        }
        if (p + 4 > len) {
            return;
        }
        uint16_t qtype = readU16(buf + p, true);
        p += 2;
        p += 2;  // qclass
        if (i == 0) {
            m.dnsQueryName = name;
            m.dnsQueryType = qtype;
            m.dnsQueryTypeName = dnsTypeName(qtype);
            m.dnsQueryCount = qd;
        }
    }

    for (int i = 0; i < an; i++) {
        DnsAnswer a;
        if (!readDnsName(buf, len, &p, a.name)) {
            return;
        }
        if (p + 10 > len) {
            return;
        }
        a.type = readU16(buf + p, true);
        p += 2;
        p += 2;  // class
        uint32_t ttl = readU32(buf + p, true);
        p += 4;
        a.ttl = (int)ttl;
        a.doBit = (ttl & 0x80000000u) != 0;
        uint16_t rdlen = readU16(buf + p, true);
        p += 2;
        if (p + rdlen > len) {
            return;
        }
        const uint8_t* rdata = buf + p;
        switch (a.type) {
            case 1:
                if (rdlen == 4) {
                    a.ips.push_back(v4ToText(rdata));
                }
                break;
            case 28:
                if (rdlen == 16) {
                    a.ips.push_back(v6ToText(rdata));
                }
                break;
            case 2:   // NS
            case 12:  // PTR
            case 39: { // DNAME
                size_t q = p;
                std::string target;
                if (readDnsName(buf, len, &q, target)) {
                    a.values.push_back(target);
                }
                break;
            }
            case 15: { // MX
                size_t q = p;
                if (rdlen >= 2) {
                    uint16_t pref = readU16(buf + q, true);
                    q += 2;
                    std::string exch;
                    if (readDnsName(buf, len, &q, exch)) {
                        a.values.push_back("MX:" + std::to_string(pref) + " " + exch);
                    }
                }
                break;
            }
            case 16: { // TXT
                std::string txt;
                size_t q = p;
                size_t end = p + rdlen;
                while (q < end) {
                    if (q + 1 > len) {
                        break;
                    }
                    uint8_t slen = buf[q];
                    q += 1;
                    if (q + slen > end) {
                        break;
                    }
                    txt.append((const char*)buf + q, slen);
                    q += slen;
                }
                if (!txt.empty()) {
                    a.values.push_back("TXT:" + txt);
                }
                break;
            }
            case 33: { // SRV
                size_t q = p;
                if (rdlen >= 6) {
                    uint16_t pri = readU16(buf + q, true);
                    uint16_t weight = readU16(buf + q + 2, true);
                    uint16_t port = readU16(buf + q + 4, true);
                    q += 6;
                    std::string target;
                    if (readDnsName(buf, len, &q, target)) {
                        a.values.push_back("SRV:" + std::to_string(pri) + " " +
                                           std::to_string(weight) + " " +
                                           std::to_string(port) + " " + target);
                    }
                }
                break;
            }
            default:
                break;
        }
        p += rdlen;
        m.dnsAnswers.push_back(a);
    }

    for (int i = 0; i < ns; i++) {
        std::string name;
        if (!readDnsName(buf, len, &p, name)) {
            return;
        }
        if (p + 10 > len) {
            return;
        }
        p += 2;  // type
        p += 2;  // class
        p += 4;  // ttl
        uint16_t rdlen = readU16(buf + p, true);
        p += 2 + rdlen;
        if (p > len) {
            return;
        }
    }

    for (int i = 0; i < ar; i++) {
        std::string name;
        if (!readDnsName(buf, len, &p, name)) {
            return;
        }
        if (p + 10 > len) {
            return;
        }
        int rtype = readU16(buf + p, true);
        uint32_t rttl = readU32(buf + p + 4, true);
        if (rtype == 41) {
            m.dnsEdns = true;
            if (rttl & 0x80000000u) {
                m.dnsDoBit = true;
            }
        }
        p += 2;  // type
        p += 2;  // class
        p += 4;  // ttl
        uint16_t rdlen = readU16(buf + p, true);
        p += 2 + rdlen;
        if (p > len) {
            return;
        }
    }
}

bool isDnsPort(uint16_t srcPort, uint16_t dstPort) {
    return srcPort == 53 || dstPort == 53 || srcPort == 853 || dstPort == 853 ||
           srcPort == 5353 || dstPort == 5353;
}

void parseTcp(const uint8_t* data, size_t len, PacketMetadata& m) {
    if (len < 20) {
        return;
    }
    m.hasTcp = true;
    m.tcpSrcPort = readU16(data, true);
    m.tcpDstPort = readU16(data + 2, true);
    m.tcpSeq = readU32(data + 4, true);
    m.tcpFlags = (uint16_t)data[13];
    m.syn = (m.tcpFlags & 0x02) != 0;
    m.fin = (m.tcpFlags & 0x01) != 0;
    m.rst = (m.tcpFlags & 0x04) != 0;
    uint8_t doff = (data[12] >> 4) & 0x0F;
    // A TCP header is at least 20 bytes. Do not parse payload when the
    // advertised header length is invalid or extends beyond this IP packet.
    if (doff < 5) {
        m.hasTcp = false;
        return;
    }
    size_t hdr = (size_t)doff * 4;
    if (hdr > len) {
        m.hasTcp = false;
        return;
    }
    size_t paylen = len - hdr;
    m.tcpDataLength = (int)paylen;
    if (paylen > 0) {
        m.tcpPayload.assign((const char*)data + hdr, paylen);
    }
    if (isDnsPort(m.tcpSrcPort, m.tcpDstPort) && paylen >= 14) {
        // DNS over TCP starts with a two-byte message length.
        const uint8_t* dns = (const uint8_t*)m.tcpPayload.data();
        size_t dnsLen = readU16(dns, true);
        if (dnsLen >= 12 && dnsLen <= paylen - 2) {
            parseDnsMessage(dns + 2, dnsLen, m);
        }
    }
}

void parseUdp(const uint8_t* data, size_t len, PacketMetadata& m) {
    if (len < 8) {
        return;
    }
    uint16_t udpLength = readU16(data + 4, true);
    if (udpLength < 8 || udpLength > len) {
        return;
    }
    m.hasUdp = true;
    m.udpSrcPort = readU16(data, true);
    m.udpDstPort = readU16(data + 2, true);
    size_t paylen = udpLength - 8;
    if (paylen > 0) {
        m.udpPayload.assign((const char*)data + 8, paylen);
    }
    if (isDnsPort(m.udpSrcPort, m.udpDstPort) && paylen >= 12) {
        parseDnsMessage((const uint8_t*)m.udpPayload.data(), paylen, m);
    }
}

void parseIpv4(const uint8_t* data, size_t len, PacketMetadata& m) {
    if (len < 20 || (data[0] >> 4) != 4) {
        return;
    }

    size_t headerLength = (size_t)(data[0] & 0x0F) * 4;
    if (headerLength < 20 || headerLength > len) {
        return;
    }

    uint16_t totalLength = readU16(data + 2, true);
    if (totalLength < headerLength) {
        return;
    }

    size_t packetLength = totalLength < len ? totalLength : len;
    m.hasIp = true;
    m.isIpv6 = false;
    m.ipProtocol = data[9];
    m.srcIp = IpAddress::v4FromBytes(data + 12);
    m.dstIp = IpAddress::v4FromBytes(data + 16);
    m.ipTotalLength = totalLength;

    uint16_t fragment = readU16(data + 6, true);
    m.ipFlags = (uint8_t)((fragment >> 13) & 0x07);
    m.ipFragOffset = fragment & 0x1FFF;
    m.isFragment = (m.ipFlags & 0x01) != 0 || m.ipFragOffset != 0;

    // The transport header appears only in the first fragment. Even there,
    // parsing it as a complete datagram would produce misleading payload data.
    if (m.isFragment) {
        return;
    }

    size_t payloadLength = packetLength - headerLength;
    if (m.ipProtocol == 6 && payloadLength >= 20) {
        parseTcp(data + headerLength, payloadLength, m);
    } else if (m.ipProtocol == 17 && payloadLength >= 8) {
        parseUdp(data + headerLength, payloadLength, m);
    }
}

void parseIpv6(const uint8_t* data, size_t len, PacketMetadata& m) {
    if (len < 40 || (data[0] >> 4) != 6) {
        return;
    }

    uint16_t payloadLength = readU16(data + 4, true);
    size_t packetLength = 40 + (size_t)payloadLength;
    if (packetLength > len) {
        packetLength = len;
    }

    m.hasIp = true;
    m.isIpv6 = true;
    for (int i = 0; i < 16; i++) {
        m.srcIp.v6[i] = data[8 + i];
        m.dstIp.v6[i] = data[24 + i];
    }
    m.srcIp.isIpv6 = true;
    m.dstIp.isIpv6 = true;
    m.ipTotalLength = 40 + payloadLength;

    uint8_t nextHeader = data[6];
    size_t offset = 40;
    int extensions = 0;

    while (nextHeader == 0 || nextHeader == 43 || nextHeader == 60 ||
           nextHeader == 44) {
        if (++extensions > 16 || offset + 2 > packetLength) {
            return;
        }

        uint8_t followingHeader = data[offset];
        size_t extensionLength = 0;
        if (nextHeader == 44) {
            if (offset + 8 > packetLength) {
                return;
            }
            uint16_t fragment = readU16(data + offset + 2, true);
            m.ipFragOffset = (fragment >> 3) & 0x1FFF;
            m.isFragment = true;
            extensionLength = 8;
        } else {
            extensionLength = ((size_t)data[offset + 1] + 1) * 8;
            if (offset + extensionLength > packetLength) {
                return;
            }
        }

        offset += extensionLength;
        nextHeader = followingHeader;

        // Fragmented IPv6 packets need reassembly before transport parsing.
        if (m.isFragment) {
            m.ipProtocol = nextHeader;
            return;
        }
    }

    m.ipProtocol = nextHeader;
    if (offset > packetLength) {
        return;
    }

    size_t remaining = packetLength - offset;
    if (nextHeader == 6 && remaining >= 20) {
        parseTcp(data + offset, remaining, m);
    } else if (nextHeader == 17 && remaining >= 8) {
        parseUdp(data + offset, remaining, m);
    }
}

void parseEthernet(const uint8_t* data, size_t len, PacketMetadata& m) {
    if (len < 14) {
        return;
    }
    m.hasEthernet = true;
    for (int i = 0; i < 6; i++) {
        m.dstMac.bytes[i] = data[i];
        m.srcMac.bytes[i] = data[6 + i];
    }
    uint16_t etherType = readU16(data + 12, true);
    size_t off = 14;
    while ((etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100) &&
           off + 4 <= len) {
        etherType = readU16(data + off + 2, true);
        off += 4;
    }
    m.etherType = etherType;
    if (etherType == 0x0800 && off + 20 <= len) {
        parseIpv4(data + off, len - off, m);
    } else if (etherType == 0x86DD && off + 40 <= len) {
        parseIpv6(data + off, len - off, m);
    }
}

void parseRawIp(const uint8_t* data, size_t len, PacketMetadata& m) {
    if (len < 1) {
        return;
    }
    uint8_t version = (data[0] >> 4) & 0x0F;
    if (version == 4) {
        parseIpv4(data, len, m);
    } else if (version == 6) {
        parseIpv6(data, len, m);
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.x parsing

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) {
        return std::string();
    }
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string toLower(const std::string& s) {
    std::string out(s);
    for (auto& c : out) {
        c = (char)tolower((unsigned char)c);
    }
    return out;
}

size_t findLineEnd(const std::string& s, size_t pos) {
    size_t nl = s.find('\n', pos);
    if (nl == std::string::npos) {
        return std::string::npos;
    }
    return nl + 1;
}

bool isHttpRequestStart(const std::string& s, size_t pos) {
    size_t sp1 = s.find(' ', pos);
    if (sp1 == std::string::npos || sp1 - pos > 8) {
        return false;
    }
    std::string method = s.substr(pos, sp1 - pos);
    if (method.empty()) {
        return false;
    }
    for (char c : method) {
        if (c < 'A' || c > 'Z') {
            return false;
        }
    }
    size_t sp2 = s.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) {
        return false;
    }
    return s.compare(sp2 + 1, 5, "HTTP/") == 0;
}

bool isHttpResponseStart(const std::string& s, size_t pos) {
    return pos + 5 <= s.size() && s.compare(pos, 5, "HTTP/") == 0;
}

struct HttpHeaders {
    std::string host;
    std::string userAgent;
    std::string referer;
    std::string contentType;
    std::string server;
    std::string location;
    long long contentLength = -1;
    bool chunked = false;

    void parseLine(const std::string& line) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) {
            return;
        }
        std::string name = toLower(trim(line.substr(0, colon)));
        std::string value = trim(line.substr(colon + 1));
        if (name == "host") {
            host = value;
        } else if (name == "user-agent") {
            userAgent = value;
        } else if (name == "referer") {
            referer = value;
        } else if (name == "content-type") {
            contentType = value;
        } else if (name == "server") {
            server = value;
        } else if (name == "location") {
            location = value;
        } else if (name == "content-length") {
            contentLength = strtoll(value.c_str(), nullptr, 10);
        } else if (name == "transfer-encoding" &&
                   toLower(value).find("chunked") != std::string::npos) {
            chunked = true;
        }
    }
};

size_t skipChunked(const std::string& s, size_t pos) {
    while (pos + 1 < s.size()) {
        char* endp = nullptr;
        long size = strtol(s.c_str() + pos, &endp, 16);
        if (endp == s.c_str() + pos) {
            return pos;
        }
        if (size < 0) {
            return s.size();
        }
        pos = (size_t)(endp - s.c_str());
        while (pos < s.size() && s[pos] != '\n') {
            pos++;
        }
        if (pos < s.size()) {
            pos++;
        }
        if (size == 0) {
            while (pos < s.size()) {
                size_t eol = s.find('\n', pos);
                if (eol == std::string::npos) {
                    return s.size();
                }
                if (eol == pos) {
                    return eol + 1;
                }
                pos = eol + 1;
            }
            return s.size();
        }
        pos += (size_t)size;
        if (pos + 2 <= s.size() && s[pos] == '\r' && s[pos + 1] == '\n') {
            pos += 2;
        } else if (pos < s.size() && s[pos] == '\n') {
            pos += 1;
        }
    }
    return s.size();
}

size_t skipBody(const std::string& s, size_t pos, const HttpHeaders& h) {
    if (h.chunked) {
        return skipChunked(s, pos);
    }
    if (h.contentLength >= 0) {
        size_t end = pos + (size_t)h.contentLength;
        return end <= s.size() ? end : s.size();
    }
    return pos;
}

}  // namespace

std::string MacAddress::text() const {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0],
             bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    return std::string(buf);
}

std::string IpAddress::text() const {
    if (!isIpv6) {
        return v4ToText(v4);
    }
    return v6ToText(v6);
}

IpAddress IpAddress::v4FromBytes(const uint8_t* p) {
    IpAddress a;
    a.isIpv6 = false;
    memcpy(a.v4, p, 4);
    return a;
}

IpAddress IpAddress::v6FromBytes(const uint8_t* p) {
    IpAddress a;
    a.isIpv6 = true;
    memcpy(a.v6, p, 16);
    return a;
}

PacketMetadata parsePacket(const uint8_t* data, size_t len, int linkType) {
    PacketMetadata m;
    m.frameLength = (int)len;
    if (linkType == 1) {
        parseEthernet(data, len, m);
    } else if (linkType == 0 || linkType == 101) {
        parseRawIp(data, len, m);
    }
    return m;
}

HttpMessages parseHttpMessages(const std::string& stream) {
    HttpMessages out;
    size_t pos = 0;
    while (pos < stream.size()) {
        bool isRequest = isHttpRequestStart(stream, pos);
        if (!isRequest && !isHttpResponseStart(stream, pos)) {
            break;
        }
        size_t lineEnd = findLineEnd(stream, pos);
        if (lineEnd == std::string::npos) {
            break;
        }
        std::string line = stream.substr(pos, lineEnd - pos);
        HttpHeaders headers;
        if (isRequest) {
            size_t sp1 = line.find(' ');
            size_t sp2 = line.find(' ', sp1 + 1);
            if (sp2 == std::string::npos) {
                break;
            }
            HttpRequest req;
            req.method = trim(line.substr(0, sp1));
            req.target = trim(line.substr(sp1 + 1, sp2 - sp1 - 1));
            req.version = trim(line.substr(sp2 + 1));
            if (req.target.empty() || req.method.empty()) {
                break;
            }
            size_t hpos = lineEnd;
            while (hpos < stream.size()) {
                size_t he = findLineEnd(stream, hpos);
                if (he == std::string::npos) {
                    break;
                }
                std::string hline = stream.substr(hpos, he - hpos);
                if (trim(hline).empty()) {
                    hpos = he;
                    break;
                }
                headers.parseLine(hline);
                hpos = he;
            }
            req.hostHeader = headers.host;
            req.userAgent = headers.userAgent;
            req.referer = headers.referer;
            req.contentType = headers.contentType;
            req.contentLength = headers.contentLength;
            out.requests.push_back(req);
            if (!headers.host.empty()) {
                out.hosts.push_back(headers.host);
            }
            if (!headers.userAgent.empty()) {
                out.userAgents.push_back(headers.userAgent);
            }
            out.paths.push_back(req.target);
            size_t next = skipBody(stream, hpos, headers);
            if (next == std::string::npos || next <= pos) {
                break;
            }
            pos = next;
        } else {
            size_t sp = line.find(' ');
            if (sp == std::string::npos) {
                break;
            }
            HttpResponse resp;
            resp.version = trim(line.substr(0, sp));
            size_t sp2 = line.find(' ', sp + 1);
            if (sp2 == std::string::npos) {
                sp2 = line.size();
            }
            resp.status = atoi(trim(line.substr(sp + 1, sp2 - sp - 1)).c_str());
            resp.reason = trim(line.substr(sp2 + 1));
            size_t hpos = lineEnd;
            while (hpos < stream.size()) {
                size_t he = findLineEnd(stream, hpos);
                if (he == std::string::npos) {
                    break;
                }
                std::string hline = stream.substr(hpos, he - hpos);
                if (trim(hline).empty()) {
                    hpos = he;
                    break;
                }
                headers.parseLine(hline);
                hpos = he;
            }
            resp.server = headers.server;
            resp.contentType = headers.contentType;
            resp.location = headers.location;
            resp.contentLength = headers.contentLength;
            out.responses.push_back(resp);
            if (resp.status == 404) {
                out.status404++;
            }
            if (resp.status >= 500) {
                out.status5xx++;
            }
            size_t next = skipBody(stream, hpos, headers);
            if (next == std::string::npos || next <= pos) {
                break;
            }
            pos = next;
        }
    }
    return out;
}
