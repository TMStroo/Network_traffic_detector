#ifndef NTA_PACKET_H
#define NTA_PACKET_H

#include <cstdint>
#include <string>
#include <vector>

// Physical MAC address in canonical "aa:bb:cc:dd:ee:ff" text form.
struct MacAddress {
    uint8_t bytes[6] = {0, 0, 0, 0, 0, 0};

    // Input: none. Output: canonical text form of the address.
    std::string text() const;
};

// IP address, either IPv4 or IPv6.
struct IpAddress {
    bool isIpv6 = false;
    uint8_t v4[4] = {0, 0, 0, 0};
    uint8_t v6[16] = {0};

    // Input: none. Output: canonical text form of the address.
    std::string text() const;
    // Input: pointer to 4 raw bytes. Output: IpAddress with the IPv4 family set.
    static IpAddress v4FromBytes(const uint8_t* p);
    // Input: pointer to 16 raw bytes. Output: IpAddress with the IPv6 family set.
    static IpAddress v6FromBytes(const uint8_t* p);
};

// One DNS resource record extracted from a DNS message.
struct DnsAnswer {
    std::string name;
    int type = 0;              // 1=A, 2=NS, 5=CNAME, 12=PTR, 15=MX, 16=TXT, 28=AAAA, 33=SRV, ...
    int ttl = 0;
    bool doBit = false;
    std::vector<std::string> ips;    // A / AAAA addresses
    std::vector<std::string> values; // decoded text values for other types
};

// One HTTP/1.x request message.
struct HttpRequest {
    std::string method;
    std::string target;      // path, e.g. "/api/users?x=1"
    std::string version;     // e.g. "HTTP/1.1"
    std::string hostHeader;
    std::string userAgent;
    std::string referer;
    std::string contentType;
    long long contentLength = -1;
};

// One HTTP/1.x response message.
struct HttpResponse {
    int status = 0;          // e.g. 200, 404
    std::string reason;      // e.g. "OK"
    std::string version;
    std::string server;
    std::string contentType;
    std::string location;
    long long contentLength = -1;
};

// All HTTP messages found in one reassembled stream.
struct HttpMessages {
    std::vector<HttpRequest> requests;
    std::vector<HttpResponse> responses;
    std::vector<std::string> paths;      // unique request targets
    std::vector<std::string> userAgents; // unique user agents
    std::vector<std::string> hosts;      // unique request Host headers
    int status404 = 0;
    int status5xx = 0;
};

// Structured metadata parsed from one frame.
struct PacketMetadata {
    int64_t timestampUs = 0;
    int frameLength = 0;

    bool hasEthernet = false;
    MacAddress srcMac;
    MacAddress dstMac;
    uint16_t etherType = 0;

    bool hasIp = false;
    bool isIpv6 = false;
    IpAddress srcIp;
    IpAddress dstIp;
    int ipProtocol = 0;
    int64_t ipTotalLength = 0;
    uint8_t ipFlags = 0;
    int ipFragOffset = 0;
    bool isFragment = false;

    bool hasTcp = false;
    uint16_t tcpSrcPort = 0;
    uint16_t tcpDstPort = 0;
    uint32_t tcpSeq = 0;
    uint16_t tcpFlags = 0;
    bool syn = false;
    bool fin = false;
    bool rst = false;
    int tcpDataLength = 0;
    std::string tcpPayload;

    bool hasUdp = false;
    uint16_t udpSrcPort = 0;
    uint16_t udpDstPort = 0;
    std::string udpPayload;

    bool hasDns = false;
    std::string dnsQueryName;
    int dnsQueryType = 0;
    std::string dnsQueryTypeName;
    int dnsQueryCount = 0;
    bool dnsIsResponse = false;
    int dnsRcode = 0;
    bool dnsTruncated = false;
    bool dnsRecursionAvailable = false;
    bool dnsEdns = false;
    bool dnsDoBit = false;
    std::vector<DnsAnswer> dnsAnswers;
};

// Parses raw bytes into structured metadata.
// Input: pointer to the frame bytes, number of bytes available, link type (1=Ethernet).
// Output: PacketMetadata; hasEthernet/hasIp/hasTcp/hasUdp/hasDns are set as far as parsing got.
PacketMetadata parsePacket(const uint8_t* data, size_t len, int linkType);

// Parses HTTP/1.x messages from a reassembled byte stream.
// Input: stream bytes.
// Output: HttpMessages with all requests, responses and header values found.
HttpMessages parseHttpMessages(const std::string& stream);

#endif
