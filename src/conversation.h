#ifndef NTA_CONVERSATION_H
#define NTA_CONVERSATION_H

#include "packet.h"
#include "storage.h"

#include <map>
#include <string>
#include <tuple>
#include <vector>

// Identifies one network session by its five-tuple (6 = TCP, 17 = UDP).
struct ConversationKey {
    std::string srcIp;
    uint16_t srcPort = 0;
    std::string dstIp;
    uint16_t dstPort = 0;
    int protocol = 0;

    bool operator<(const ConversationKey& o) const {
        return std::tie(srcIp, srcPort, dstIp, dstPort, protocol) <
               std::tie(o.srcIp, o.srcPort, o.dstIp, o.dstPort, o.protocol);
    }
};

// One DNS question or response seen on the wire.
struct DnsQueryEvent {
    int64_t timestampUs = 0;
    std::string name;
    int qtype = 0;
    std::string typeName;
    bool isResponse = false;
    int rcode = 0;
    std::vector<std::string> answers;  // textual answers (ips and decoded values)
};

// One reconstructed network conversation between two hosts.
struct Conversation {
    ConversationKey key;
    int64_t firstPacketUs = 0;
    int64_t lastPacketUs = 0;
    int64_t synTimeUs = -1;  // time of the first TCP SYN, or -1
    bool sawRst = false;
    uint64_t packetCount = 0;
    uint64_t totalBytes = 0;       // sum of IP packet lengths
    uint64_t totalPayloadBytes = 0;  // TCP data length or UDP payload bytes
    std::string stream;            // reassembled TCP stream or concatenated UDP payloads
    std::vector<int64_t> eventTimes;  // timestamps of significant events
    bool hasDns = false;
    std::vector<DnsQueryEvent> dnsQueries;
    HttpMessages http;
};

// Groups traffic by host.
// Input: conversations to summarize, host MAC addresses seen per IP.
// Output: one HostRecord per IP, with packet counts and byte volumes.
std::vector<HostRecord> aggregateHosts(const std::vector<Conversation>& convs,
                                       const std::map<std::string, MacAddress>& hostMacs);

// Converts an in-memory conversation to the storage record form.
// Input: conversation, capture id, host record ids of both endpoints.
// Output: ConversationRecord ready for Storage::insertConversations.
ConversationRecord toConversationRecord(const Conversation& conv,
                                        int64_t captureId,
                                        int64_t srcHostId,
                                        int64_t dstHostId);

// Rebuilds conversations from parsed packets.
class ConversationTracker {
public:
    // Input: one parsed packet.
    // Output: none; the packet is folded into the conversation set.
    void addPacket(const PacketMetadata& p);

    // Input: none.
    // Output: all conversations, ordered by first packet time then five-tuple.
    std::vector<Conversation> finish();

    // MAC addresses seen per host IP.
    std::map<std::string, MacAddress> hostMacs;

private:
    struct FlowState {
        uint32_t expectedSeq = 0;
        bool hasExpected = false;
        std::string stream;
        std::vector<std::pair<uint32_t, std::string>> pending;
        void addSegment(uint32_t seq, const std::string& data);
    };

    ConversationKey keyOf(const PacketMetadata& p) const;

    std::map<ConversationKey, Conversation> convs_;
    std::map<ConversationKey, FlowState> flows_;
};

#endif
