#include "storage.h"

#include <cstdio>
#include <cstdlib>

namespace {

class Stmt {
public:
    Stmt(sqlite3* db, const std::string& sql) {
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt_, nullptr) != SQLITE_OK) {
            failed_ = true;
        }
    }
    ~Stmt() { sqlite3_finalize(stmt_); }

    bool failed() const { return failed_; }

    Stmt& bindText(int idx, const std::string& v) {
        sqlite3_bind_text(stmt_, idx, v.c_str(), (int)v.size(), SQLITE_TRANSIENT);
        return *this;
    }
    Stmt& bindInt64(int idx, int64_t v) {
        sqlite3_bind_int64(stmt_, idx, v);
        return *this;
    }
    Stmt& bindDouble(int idx, double v) {
        sqlite3_bind_double(stmt_, idx, v);
        return *this;
    }

    // Runs the statement and advances one step. Returns true when a row is ready.
    bool step() {
        return sqlite3_step(stmt_) == SQLITE_ROW;
    }
    // Runs the statement to completion. Returns true when done without error.
    bool run() {
        return sqlite3_step(stmt_) == SQLITE_DONE;
    }

    std::string colText(int i) const {
        const unsigned char* t = sqlite3_column_text(stmt_, i);
        return t ? std::string((const char*)t) : std::string();
    }
    int64_t colInt64(int i) const { return sqlite3_column_int64(stmt_, i); }
    double colDouble(int i) const { return sqlite3_column_double(stmt_, i); }

private:
    sqlite3_stmt* stmt_ = nullptr;
    bool failed_ = false;
};

std::string sqlMessage(sqlite3* db) {
    const char* m = sqlite3_errmsg(db);
    return m ? std::string(m) : "sqlite error";
}

// Escapes single quotes so filter strings are safe inside SQL literals.
std::string sqlEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\'') {
            out += "\'\'";
        } else {
            out += c;
        }
    }
    return out;
}

std::string likeFilter(const std::string& value) {
    return "LIKE '%" + sqlEscape(value) + "%'";
}

const char* kSchema[] = {
    "CREATE TABLE IF NOT EXISTS captures("
    "id INTEGER PRIMARY KEY, "
    "path TEXT NOT NULL, "
    "fileSize INTEGER NOT NULL DEFAULT 0, "
    "packets INTEGER NOT NULL DEFAULT 0, "
    "bytes INTEGER NOT NULL DEFAULT 0, "
    "firstPacketUs INTEGER NOT NULL DEFAULT 0, "
    "lastPacketUs INTEGER NOT NULL DEFAULT 0, "
    "createdAt TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));",
    "CREATE TABLE IF NOT EXISTS hosts("
    "id INTEGER PRIMARY KEY, "
    "ip TEXT NOT NULL UNIQUE, "
    "mac TEXT NOT NULL DEFAULT '', "
    "firstSeenUs INTEGER NOT NULL DEFAULT 0, "
    "lastSeenUs INTEGER NOT NULL DEFAULT 0, "
    "packetCount INTEGER NOT NULL DEFAULT 0, "
    "bytesSent INTEGER NOT NULL DEFAULT 0, "
    "bytesReceived INTEGER NOT NULL DEFAULT 0);",
    "CREATE TABLE IF NOT EXISTS conversations("
    "id INTEGER PRIMARY KEY, "
    "srcIp TEXT NOT NULL, "
    "srcPort INTEGER NOT NULL DEFAULT 0, "
    "dstIp TEXT NOT NULL, "
    "dstPort INTEGER NOT NULL DEFAULT 0, "
    "protocol INTEGER NOT NULL DEFAULT 0, "
    "srcHostId INTEGER NOT NULL DEFAULT 0, "
    "dstHostId INTEGER NOT NULL DEFAULT 0, "
    "captureId INTEGER NOT NULL DEFAULT 0, "
    "startUs INTEGER NOT NULL DEFAULT 0, "
    "endUs INTEGER NOT NULL DEFAULT 0, "
    "packetCount INTEGER NOT NULL DEFAULT 0, "
    "totalBytes INTEGER NOT NULL DEFAULT 0, "
    "totalPayloadBytes INTEGER NOT NULL DEFAULT 0, "
    "isDns INTEGER NOT NULL DEFAULT 0, "
    "dnsQueryName TEXT NOT NULL DEFAULT '', "
    "dnsQueryType INTEGER NOT NULL DEFAULT 0, "
    "dnsQueryTypeName TEXT NOT NULL DEFAULT '', "
    "isHttp INTEGER NOT NULL DEFAULT 0, "
    "httpRequests INTEGER NOT NULL DEFAULT 0, "
    "httpResponses INTEGER NOT NULL DEFAULT 0, "
    "status404 INTEGER NOT NULL DEFAULT 0, "
    "status5xx INTEGER NOT NULL DEFAULT 0, "
    "httpMethods TEXT NOT NULL DEFAULT '', "
    "httpPaths TEXT NOT NULL DEFAULT '', "
    "httpUserAgents TEXT NOT NULL DEFAULT '', "
    "httpHostHeaders TEXT NOT NULL DEFAULT '');",
    "CREATE TABLE IF NOT EXISTS dns_queries("
    "id INTEGER PRIMARY KEY, "
    "conversationId INTEGER NOT NULL DEFAULT 0, "
    "captureId INTEGER NOT NULL DEFAULT 0, "
    "host TEXT NOT NULL DEFAULT '', "
    "name TEXT NOT NULL, "
    "qtype INTEGER NOT NULL DEFAULT 0, "
    "typeName TEXT NOT NULL DEFAULT '', "
    "timestampUs INTEGER NOT NULL DEFAULT 0, "
    "isResponse INTEGER NOT NULL DEFAULT 0, "
    "rcode INTEGER NOT NULL DEFAULT 0, "
    "answers TEXT NOT NULL DEFAULT '');",
    "CREATE TABLE IF NOT EXISTS http_events("
    "id INTEGER PRIMARY KEY, "
    "conversationId INTEGER NOT NULL DEFAULT 0, "
    "captureId INTEGER NOT NULL DEFAULT 0, "
    "host TEXT NOT NULL DEFAULT '', "
    "kind TEXT NOT NULL, "
    "method TEXT NOT NULL DEFAULT '', "
    "path TEXT NOT NULL DEFAULT '', "
    "hostHeader TEXT NOT NULL DEFAULT '', "
    "userAgent TEXT NOT NULL DEFAULT '', "
    "referer TEXT NOT NULL DEFAULT '', "
    "contentType TEXT NOT NULL DEFAULT '', "
    "server TEXT NOT NULL DEFAULT '', "
    "location TEXT NOT NULL DEFAULT '', "
    "status INTEGER NOT NULL DEFAULT 0, "
    "timestampUs INTEGER NOT NULL DEFAULT 0);",
    "CREATE TABLE IF NOT EXISTS anomalies("
    "id INTEGER PRIMARY KEY, "
    "conversationId INTEGER NOT NULL DEFAULT 0, "
    "captureId INTEGER NOT NULL DEFAULT 0, "
    "type TEXT NOT NULL, "
    "severity TEXT NOT NULL, "
    "subject TEXT NOT NULL DEFAULT '', "
    "evidence TEXT NOT NULL DEFAULT '', "
    "explanation TEXT NOT NULL DEFAULT '', "
    "confidence REAL NOT NULL DEFAULT 0, "
    "firstDetectedUs INTEGER NOT NULL DEFAULT 0, "
    "lastSeenUs INTEGER NOT NULL DEFAULT 0, "
    "eventCount INTEGER NOT NULL DEFAULT 0);",
    "CREATE INDEX IF NOT EXISTS idx_conversations_hosts ON conversations(srcIp, dstIp);",
    "CREATE INDEX IF NOT EXISTS idx_conversations_capture ON conversations(captureId);",
    "CREATE INDEX IF NOT EXISTS idx_dns_queries_host ON dns_queries(host, timestampUs);",
    "CREATE INDEX IF NOT EXISTS idx_anomalies_subject ON anomalies(subject);",
    "CREATE TABLE IF NOT EXISTS packets("
    "id INTEGER PRIMARY KEY, "
    "captureId INTEGER NOT NULL DEFAULT 0, "
    "timestampUs INTEGER NOT NULL DEFAULT 0, "
    "protocol INTEGER NOT NULL DEFAULT 0, "
    "srcIp TEXT NOT NULL DEFAULT '', "
    "dstIp TEXT NOT NULL DEFAULT '', "
    "srcPort INTEGER NOT NULL DEFAULT 0, "
    "dstPort INTEGER NOT NULL DEFAULT 0, "
    "bytes INTEGER NOT NULL DEFAULT 0);",
    "CREATE INDEX IF NOT EXISTS idx_packets_capture ON packets(captureId, timestampUs);",
};

std::string joinAnswers(const std::vector<std::string>& answers) {
    std::string out;
    for (size_t i = 0; i < answers.size(); i++) {
        if (answers[i].empty()) {
            continue;
        }
        if (!out.empty()) {
            out += " | ";
        }
        out += answers[i];
    }
    return out;
}

std::string sqlInt(long long v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld", v);
    return std::string(buf);
}

}  // namespace

Storage::~Storage() { close(); }

bool Storage::open(const std::string& path, std::string& message) {
    close();
    if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
        message = sqlMessage(db_);
        if (db_ != nullptr) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return false;
    }
    return true;
}

void Storage::close() {
    if (db_ != nullptr) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool Storage::initSchema(std::string& message) {
    for (const char* sql : kSchema) {
        if (sqlite3_exec(db_, sql, nullptr, nullptr, nullptr) != SQLITE_OK) {
            message = sqlMessage(db_);
            return false;
        }
    }
    return true;
}

bool Storage::insertCapture(CaptureRecord& cap, std::string& message) {
    Stmt s(db_, "INSERT INTO captures(path, fileSize, packets, bytes, "
                "firstPacketUs, lastPacketUs) VALUES(?, ?, ?, ?, ?, ?)");
    if (s.failed()) {
        message = sqlMessage(db_);
        return false;
    }
    s.bindText(1, cap.path)
        .bindInt64(2, cap.fileSize)
        .bindInt64(3, cap.packets)
        .bindInt64(4, cap.bytes)
        .bindInt64(5, cap.firstPacketUs)
        .bindInt64(6, cap.lastPacketUs);
    if (!s.run()) {
        message = sqlMessage(db_);
        return false;
    }
    cap.id = sqlite3_last_insert_rowid(db_);
    return true;
}

bool Storage::insertHosts(const std::vector<HostRecord>& hosts, std::string& message) {
    for (const HostRecord& h : hosts) {
        Stmt s(db_, "INSERT INTO hosts(ip, mac, firstSeenUs, lastSeenUs, "
                    "packetCount, bytesSent, bytesReceived) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(ip) DO UPDATE SET "
                    "mac = COALESCE(NULLIF(excluded.mac, ''), hosts.mac), "
                    "firstSeenUs = CASE WHEN hosts.firstSeenUs = 0 "
                    "THEN excluded.firstSeenUs "
                    "ELSE MIN(hosts.firstSeenUs, excluded.firstSeenUs) END, "
                    "lastSeenUs = MAX(hosts.lastSeenUs, excluded.lastSeenUs), "
                    "packetCount = hosts.packetCount + excluded.packetCount, "
                    "bytesSent = hosts.bytesSent + excluded.bytesSent, "
                    "bytesReceived = hosts.bytesReceived + excluded.bytesReceived");
        if (s.failed()) {
            message = sqlMessage(db_);
            return false;
        }
        s.bindText(1, h.ip)
            .bindText(2, h.mac)
            .bindInt64(3, h.firstSeenUs)
            .bindInt64(4, h.lastSeenUs)
            .bindInt64(5, (int64_t)h.packetCount)
            .bindInt64(6, (int64_t)h.bytesSent)
            .bindInt64(7, (int64_t)h.bytesReceived);
        if (!s.run()) {
            message = sqlMessage(db_);
            return false;
        }
    }
    return true;
}

bool Storage::insertConversations(std::vector<ConversationRecord>& convs, std::string& message) {
    for (ConversationRecord& c : convs) {
        Stmt s(db_, "INSERT INTO conversations("
                    "srcIp, srcPort, dstIp, dstPort, protocol, srcHostId, dstHostId, "
                    "captureId, startUs, endUs, packetCount, totalBytes, totalPayloadBytes, "
                    "isDns, dnsQueryName, dnsQueryType, dnsQueryTypeName, isHttp, "
                    "httpRequests, httpResponses, status404, status5xx, "
                    "httpMethods, httpPaths, httpUserAgents, httpHostHeaders) "
                     "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        if (s.failed()) {
            message = sqlMessage(db_);
            return false;
        }
        s.bindText(1, c.srcIp)
            .bindInt64(2, c.srcPort)
            .bindText(3, c.dstIp)
            .bindInt64(4, c.dstPort)
            .bindInt64(5, c.protocol)
            .bindInt64(6, c.srcHostId)
            .bindInt64(7, c.dstHostId)
            .bindInt64(8, c.captureId)
            .bindInt64(9, c.startUs)
            .bindInt64(10, c.endUs)
            .bindInt64(11, (int64_t)c.packetCount)
            .bindInt64(12, (int64_t)c.totalBytes)
            .bindInt64(13, (int64_t)c.totalPayloadBytes)
            .bindInt64(14, c.isDns ? 1 : 0)
            .bindText(15, c.dnsQueryName)
            .bindInt64(16, c.dnsQueryType)
            .bindText(17, c.dnsQueryTypeName)
            .bindInt64(18, c.isHttp ? 1 : 0)
            .bindInt64(19, c.httpRequests)
            .bindInt64(20, c.httpResponses)
            .bindInt64(21, c.status404)
            .bindInt64(22, c.status5xx)
            .bindText(23, c.httpMethods)
            .bindText(24, c.httpPaths)
            .bindText(25, c.httpUserAgents)
            .bindText(26, c.httpHostHeaders);
        if (!s.run()) {
            message = sqlMessage(db_);
            return false;
        }
        c.id = sqlite3_last_insert_rowid(db_);
    }
    return true;
}

bool Storage::insertDnsQueries(std::vector<DnsQueryRecord>& queries, std::string& message) {
    for (DnsQueryRecord& q : queries) {
        Stmt s(db_, "INSERT INTO dns_queries("
                    "conversationId, captureId, host, name, qtype, typeName, "
                    "timestampUs, isResponse, rcode, answers) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        if (s.failed()) {
            message = sqlMessage(db_);
            return false;
        }
        s.bindInt64(1, q.conversationId)
            .bindInt64(2, q.captureId)
            .bindText(3, q.host)
            .bindText(4, q.name)
            .bindInt64(5, q.qtype)
            .bindText(6, q.typeName)
            .bindInt64(7, q.timestampUs)
            .bindInt64(8, q.isResponse ? 1 : 0)
            .bindInt64(9, q.rcode)
            .bindText(10, joinAnswers(q.answers));
        if (!s.run()) {
            message = sqlMessage(db_);
            return false;
        }
        q.id = sqlite3_last_insert_rowid(db_);
    }
    return true;
}

bool Storage::insertHttpEvents(std::vector<HttpEventRecord>& events, std::string& message) {
    for (HttpEventRecord& e : events) {
        Stmt s(db_, "INSERT INTO http_events("
                    "conversationId, captureId, host, kind, method, path, hostHeader, "
                    "userAgent, referer, contentType, server, location, status, timestampUs) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        if (s.failed()) {
            message = sqlMessage(db_);
            return false;
        }
        s.bindInt64(1, e.conversationId)
            .bindInt64(2, e.captureId)
            .bindText(3, e.host)
            .bindText(4, e.kind)
            .bindText(5, e.method)
            .bindText(6, e.path)
            .bindText(7, e.hostHeader)
            .bindText(8, e.userAgent)
            .bindText(9, e.referer)
            .bindText(10, e.contentType)
            .bindText(11, e.server)
            .bindText(12, e.location)
            .bindInt64(13, e.status)
            .bindInt64(14, e.timestampUs);
        if (!s.run()) {
            message = sqlMessage(db_);
            return false;
        }
        e.id = sqlite3_last_insert_rowid(db_);
    }
    return true;
}

bool Storage::insertAnomalies(std::vector<AnomalyRecord>& anomalies, std::string& message) {
    for (AnomalyRecord& a : anomalies) {
        Stmt s(db_, "INSERT INTO anomalies("
                    "conversationId, captureId, type, severity, subject, evidence, "
                    "explanation, confidence, firstDetectedUs, lastSeenUs, eventCount) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        if (s.failed()) {
            message = sqlMessage(db_);
            return false;
        }
        s.bindInt64(1, a.conversationId)
            .bindInt64(2, a.captureId)
            .bindText(3, a.type)
            .bindText(4, a.severity)
            .bindText(5, a.subject)
            .bindText(6, a.evidence)
            .bindText(7, a.explanation)
            .bindDouble(8, a.confidence)
            .bindInt64(9, a.firstDetectedUs)
            .bindInt64(10, a.lastSeenUs)
            .bindInt64(11, a.eventCount);
        if (!s.run()) {
            message = sqlMessage(db_);
            return false;
        }
        a.id = sqlite3_last_insert_rowid(db_);
    }
    return true;
}

bool Storage::insertPackets(const std::vector<PacketStatRecord>& packets, std::string& message) {
    for (const PacketStatRecord& p : packets) {
        Stmt s(db_, "INSERT INTO packets("
                    "captureId, timestampUs, protocol, srcIp, dstIp, srcPort, dstPort, bytes) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?)");
        if (s.failed()) {
            message = sqlMessage(db_);
            return false;
        }
        s.bindInt64(1, p.captureId)
            .bindInt64(2, p.timestampUs)
            .bindInt64(3, p.protocol)
            .bindText(4, p.srcIp)
            .bindText(5, p.dstIp)
            .bindInt64(6, p.srcPort)
            .bindInt64(7, p.dstPort)
            .bindInt64(8, p.bytes);
        if (!s.run()) {
            message = sqlMessage(db_);
            return false;
        }
    }
    return true;
}

bool Storage::findHostId(const std::string& ip, int64_t& id, std::string& message) {
    Stmt s(db_, "SELECT id FROM hosts WHERE ip = ?");
    if (s.failed()) {
        message = sqlMessage(db_);
        return false;
    }
    s.bindText(1, ip);
    if (!s.step()) {
        message = sqlMessage(db_);
        return false;
    }
    id = s.colInt64(0);
    return true;
}

bool Storage::listCaptures(std::vector<CaptureRecord>& out, std::string& message) {
    Stmt s(db_, "SELECT id, path, fileSize, packets, bytes, firstPacketUs, lastPacketUs "
                "FROM captures ORDER BY firstPacketUs, id");
    if (s.failed()) {
        message = sqlMessage(db_);
        return false;
    }
    while (s.step()) {
        CaptureRecord c;
        c.id = s.colInt64(0);
        c.path = s.colText(1);
        c.fileSize = s.colInt64(2);
        c.packets = s.colInt64(3);
        c.bytes = s.colInt64(4);
        c.firstPacketUs = s.colInt64(5);
        c.lastPacketUs = s.colInt64(6);
        out.push_back(c);
    }
    return true;
}

bool Storage::listHosts(const std::string& ipFilter, std::vector<HostRecord>& out,
                        std::string& message) {
    std::string sql = "SELECT id, ip, mac, firstSeenUs, lastSeenUs, packetCount, bytesSent, "
                      "bytesReceived FROM hosts";
    if (!ipFilter.empty()) {
        sql += " WHERE ip " + likeFilter(ipFilter);
    }
    sql += " ORDER BY packetCount DESC, ip";
    Stmt s(db_, sql);
    if (s.failed()) {
        message = sqlMessage(db_);
        return false;
    }
    while (s.step()) {
        HostRecord h;
        h.id = s.colInt64(0);
        h.ip = s.colText(1);
        h.mac = s.colText(2);
        h.firstSeenUs = s.colInt64(3);
        h.lastSeenUs = s.colInt64(4);
        h.packetCount = (uint64_t)s.colInt64(5);
        h.bytesSent = (uint64_t)s.colInt64(6);
        h.bytesReceived = (uint64_t)s.colInt64(7);
        out.push_back(h);
    }
    return true;
}

bool Storage::listConversations(const std::string& protocolFilter, const std::string& hostFilter,
                                int limit, std::vector<ConversationRecord>& out,
                                std::string& message) {
    std::string sql = "SELECT id, srcIp, srcPort, dstIp, dstPort, protocol, captureId, "
                      "packetCount, totalBytes, totalPayloadBytes, isDns, dnsQueryName, "
                      "isHttp, status404, status5xx, startUs, endUs, httpRequests, "
                      "httpResponses FROM conversations";
    std::string conds;
    if (!protocolFilter.empty()) {
        int proto = atoi(protocolFilter.c_str());
        if (proto == 0) {
            proto = protocolFilter == "tcp" ? 6 : protocolFilter == "udp" ? 17 : 0;
        }
        conds += "protocol = " + sqlInt(proto);
    }
    if (!hostFilter.empty()) {
        std::string like = likeFilter(hostFilter);
        conds += conds.empty() ? "" : " AND ";
        conds += "(srcIp " + like + " OR dstIp " + like + ")";
    }
    if (!conds.empty()) {
        sql += " WHERE " + conds;
    }
    sql += " ORDER BY totalBytes DESC";
    if (limit > 0) {
        sql += " LIMIT " + sqlInt(limit);
    }
    Stmt s(db_, sql);
    if (s.failed()) {
        message = sqlMessage(db_);
        return false;
    }
    while (s.step()) {
        ConversationRecord c;
        c.id = s.colInt64(0);
        c.srcIp = s.colText(1);
        c.srcPort = (uint16_t)s.colInt64(2);
        c.dstIp = s.colText(3);
        c.dstPort = (uint16_t)s.colInt64(4);
        c.protocol = (int)s.colInt64(5);
        c.captureId = s.colInt64(6);
        c.packetCount = (uint64_t)s.colInt64(7);
        c.totalBytes = (uint64_t)s.colInt64(8);
        c.totalPayloadBytes = (uint64_t)s.colInt64(9);
        c.isDns = s.colInt64(10) != 0;
        c.dnsQueryName = s.colText(11);
        c.isHttp = s.colInt64(12) != 0;
        c.status404 = (int)s.colInt64(13);
        c.status5xx = (int)s.colInt64(14);
        c.startUs = s.colInt64(15);
        c.endUs = s.colInt64(16);
        c.httpRequests = (int)s.colInt64(17);
        c.httpResponses = (int)s.colInt64(18);
        out.push_back(c);
    }
    return true;
}

bool Storage::listDnsQueries(const std::string& hostFilter, int64_t limit,
                             std::vector<DnsQueryRecord>& out, std::string& message) {
    std::string sql = "SELECT name, typeName, isResponse, rcode, timestampUs, host, answers "
                      "FROM dns_queries";
    if (!hostFilter.empty()) {
        sql += " WHERE host " + likeFilter(hostFilter);
    }
    sql += " ORDER BY timestampUs DESC";
    if (limit > 0) {
        sql += " LIMIT " + sqlInt(limit);
    }
    Stmt s(db_, sql);
    if (s.failed()) {
        message = sqlMessage(db_);
        return false;
    }
    while (s.step()) {
        DnsQueryRecord q;
        q.name = s.colText(0);
        q.typeName = s.colText(1);
        q.isResponse = s.colInt64(2) != 0;
        q.rcode = (int)s.colInt64(3);
        q.timestampUs = s.colInt64(4);
        q.host = s.colText(5);
        std::string answersText = s.colText(6);
        if (!answersText.empty()) {
            size_t start = 0;
            while (start <= answersText.size()) {
                size_t sep = answersText.find(" | ", start);
                if (sep == std::string::npos) {
                    q.answers.push_back(answersText.substr(start));
                    break;
                }
                q.answers.push_back(answersText.substr(start, sep - start));
                start = sep + 3;
            }
        }
        out.push_back(q);
    }
    return true;
}

bool Storage::listHttpEvents(const std::string& hostFilter, int64_t limit,
                             std::vector<HttpEventRecord>& out, std::string& message) {
    std::string sql = "SELECT conversationId, captureId, host, kind, method, path, hostHeader, "
                      "userAgent, referer, contentType, server, location, status, timestampUs "
                      "FROM http_events";
    if (!hostFilter.empty()) {
        sql += " WHERE host " + likeFilter(hostFilter);
    }
    sql += " ORDER BY timestampUs DESC";
    if (limit > 0) {
        sql += " LIMIT " + sqlInt(limit);
    }
    Stmt s(db_, sql);
    if (s.failed()) {
        message = sqlMessage(db_);
        return false;
    }
    while (s.step()) {
        HttpEventRecord e;
        e.conversationId = s.colInt64(0);
        e.captureId = s.colInt64(1);
        e.host = s.colText(2);
        e.kind = s.colText(3);
        e.method = s.colText(4);
        e.path = s.colText(5);
        e.hostHeader = s.colText(6);
        e.userAgent = s.colText(7);
        e.referer = s.colText(8);
        e.contentType = s.colText(9);
        e.server = s.colText(10);
        e.location = s.colText(11);
        e.status = (int)s.colInt64(12);
        e.timestampUs = s.colInt64(13);
        out.push_back(e);
    }
    return true;
}

bool Storage::listAnomalies(double minConfidence, const std::string& typeFilter,
                            std::vector<AnomalyRecord>& out, std::string& message) {
    std::string sql = "SELECT type, severity, subject, evidence, explanation, confidence, "
                      "captureId, eventCount, firstDetectedUs, lastSeenUs FROM anomalies";
    std::string conds;
    if (minConfidence > 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "confidence >= %.3f", minConfidence);
        conds += buf;
    }
    if (!typeFilter.empty()) {
        conds += conds.empty() ? "" : " AND ";
        conds += "type = " + std::string("'") + sqlEscape(typeFilter) + "'";
    }
    if (!conds.empty()) {
        sql += " WHERE " + conds;
    }
    sql += " ORDER BY confidence DESC, type";
    Stmt s(db_, sql);
    if (s.failed()) {
        message = sqlMessage(db_);
        return false;
    }
    while (s.step()) {
        AnomalyRecord a;
        a.type = s.colText(0);
        a.severity = s.colText(1);
        a.subject = s.colText(2);
        a.evidence = s.colText(3);
        a.explanation = s.colText(4);
        a.confidence = s.colDouble(5);
        a.captureId = s.colInt64(6);
        a.eventCount = s.colInt64(7);
        a.firstDetectedUs = s.colInt64(8);
        a.lastSeenUs = s.colInt64(9);
        out.push_back(a);
    }
    return true;
}
