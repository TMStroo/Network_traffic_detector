#ifndef NTA_STORAGE_H
#define NTA_STORAGE_H

#include "sqlite3.h"

#include <cstdint>
#include <string>
#include <vector>

struct CaptureRecord {
    int64_t id = 0;
    std::string path;
    int64_t fileSize = 0;
    int64_t packets = 0;
    int64_t bytes = 0;
    int64_t firstPacketUs = 0;
    int64_t lastPacketUs = 0;
};

struct HostRecord {
    int64_t id = 0;
    std::string ip;
    std::string mac;
    int64_t firstSeenUs = 0;
    int64_t lastSeenUs = 0;
    uint64_t packetCount = 0;
    uint64_t bytesSent = 0;
    uint64_t bytesReceived = 0;
};

struct ConversationRecord {
    int64_t id = 0;
    std::string srcIp;
    uint16_t srcPort = 0;
    std::string dstIp;
    uint16_t dstPort = 0;
    int protocol = 0;
    int64_t srcHostId = 0;
    int64_t dstHostId = 0;
    int64_t captureId = 0;
    int64_t startUs = 0;
    int64_t endUs = 0;
    uint64_t packetCount = 0;
    uint64_t totalBytes = 0;
    uint64_t totalPayloadBytes = 0;
    bool isDns = false;
    std::string dnsQueryName;
    int dnsQueryType = 0;
    std::string dnsQueryTypeName;
    bool isHttp = false;
    int httpRequests = 0;
    int httpResponses = 0;
    int status404 = 0;
    int status5xx = 0;
    std::string httpMethods;
    std::string httpPaths;
    std::string httpUserAgents;
    std::string httpHostHeaders;
};

struct DnsQueryRecord {
    int64_t id = 0;
    int64_t conversationId = 0;
    int64_t captureId = 0;
    std::string host;  // client IP that issued the query
    std::string name;
    int qtype = 0;
    std::string typeName;
    int64_t timestampUs = 0;
    bool isResponse = false;
    int rcode = 0;
    std::vector<std::string> answers;
};

struct HttpEventRecord {
    int64_t id = 0;
    int64_t conversationId = 0;
    int64_t captureId = 0;
    std::string host;  // client host of the conversation
    std::string kind;  // request or response
    std::string method;
    std::string path;
    std::string hostHeader;
    std::string userAgent;
    std::string referer;
    std::string contentType;
    std::string server;
    std::string location;
    int status = 0;
    int64_t timestampUs = 0;
};

struct AnomalyRecord {
    int64_t id = 0;
    int64_t conversationId = 0;
    int64_t captureId = 0;
    std::string type;
    std::string severity;
    std::string subject;
    std::string evidence;
    std::string explanation;
    double confidence = 0;
    int64_t firstDetectedUs = 0;
    int64_t lastSeenUs = 0;
    int64_t eventCount = 0;
};

struct PacketStatRecord {
    int64_t captureId = 0;
    int64_t timestampUs = 0;
    int protocol = 0;
    std::string srcIp;
    std::string dstIp;
    int srcPort = 0;
    int dstPort = 0;
    int64_t bytes = 0;
};

// Persistent SQLite store: captures, hosts, conversations, DNS queries,
// HTTP events and anomalies.
class Storage {
public:
    Storage() = default;
    ~Storage();

    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;

    // Input: path of the SQLite database file.
    // Output: true on success; message holds the error otherwise.
    bool open(const std::string& path, std::string& message);

    // Input: none.
    // Output: closes the database; no return value.
    void close();

    // Input: none.
    // Output: true when the database file is open for inserts and queries.
    bool isOpen() const { return db_ != nullptr; }

    // Creates tables if missing.
    // Input: none.
    // Output: true when the schema is ready; message holds the error otherwise.
    bool initSchema(std::string& message);

    // --- Inserts (each returns true on success; on failure message holds the error) ---
    bool insertCapture(CaptureRecord& cap, std::string& message);
    bool insertHosts(const std::vector<HostRecord>& hosts, std::string& message);
    bool insertConversations(std::vector<ConversationRecord>& convs, std::string& message);
    bool insertDnsQueries(std::vector<DnsQueryRecord>& queries, std::string& message);
    bool insertHttpEvents(std::vector<HttpEventRecord>& events, std::string& message);
    bool insertAnomalies(std::vector<AnomalyRecord>& anomalies, std::string& message);
    bool insertPackets(const std::vector<PacketStatRecord>& packets, std::string& message);

    // --- Queries used by reports and tools ---
    bool listCaptures(std::vector<CaptureRecord>& out, std::string& message);
    bool listHosts(const std::string& ipFilter, std::vector<HostRecord>& out, std::string& message);
    bool listConversations(const std::string& protocolFilter, const std::string& hostFilter,
                           int limit, std::vector<ConversationRecord>& out, std::string& message);
    bool listDnsQueries(const std::string& hostFilter, int64_t limit,
                        std::vector<DnsQueryRecord>& out, std::string& message);
    bool listHttpEvents(const std::string& hostFilter, int64_t limit,
                        std::vector<HttpEventRecord>& out, std::string& message);
    bool listAnomalies(double minConfidence, const std::string& typeFilter,
                       std::vector<AnomalyRecord>& out, std::string& message);
    bool findHostId(const std::string& ip, int64_t& id, std::string& message);

private:
    sqlite3* db_ = nullptr;
};

#endif
