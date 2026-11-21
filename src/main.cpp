#include "cli.h"
#include "conversation.h"
#include "correlator.h"
#include "detector.h"
#include "packet.h"
#include "pcap.h"
#include "python_stats.h"
#include "storage.h"
#include "timeline.h"

#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

const char *kVersion = "nta 1.0.0";

bool fileExists(const std::string &path) {
  struct stat st;
  return stat(path.c_str(), &st) == 0;
}

std::string defaultDbPath() {
  const char *env = getenv("NTA_DB");
  if (env != nullptr && *env != '\0') {
    return env;
  }
  return "analyze.db";
}

std::string protocolName(int protocol) {
  switch (protocol) {
  case 1:
    return "icmp";
  case 6:
    return "tcp";
  case 17:
    return "udp";
  case 41:
    return "ipv6";
  case 58:
    return "icmpv6";
  case 132:
    return "sctp";
  default:
    return "proto" + std::to_string(protocol);
  }
}

// Describes a conversation five-tuple as text; must match describeConversation
// in detector.cpp.
// Input: conversation record.
// Output: string like "10.0.0.2:1234 -> 203.0.113.5:443".
std::string describeConversationKey(const ConversationRecord &c) {
  char buf[256];
  snprintf(buf, sizeof(buf), "%s:%u -> %s:%u", c.srcIp.c_str(),
           (unsigned)c.srcPort, c.dstIp.c_str(), (unsigned)c.dstPort);
  return std::string(buf);
}

bool openStorage(Storage &storage, const Cli &cli, std::string &message) {
  std::string dbPath = cli.get("db", defaultDbPath());
  if (!fileExists(dbPath)) {
    message = "no database found at: " + dbPath;
    fprintf(stderr, "nta: %s\n", message.c_str());
    return false;
  }
  if (!storage.open(dbPath, message)) {
    fprintf(stderr, "nta: %s\n", message.c_str());
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// analyze

// Reads PCAP files, stores packets, conversations, DNS, HTTP events and
// detects anomalies.
// Input: storage (opened), cli (holds the pcap paths and options).
// Output: exit code (0 on success).
int cmdAnalyze(Storage &storage, const Cli &cli, std::string &message) {
  std::string dbPath = cli.get("db", defaultDbPath());
  if (cli.getBool("reset", false)) {
    unlink(dbPath.c_str());
  }
  if (!storage.open(dbPath, message)) {
    fprintf(stderr, "nta: %s\n", message.c_str());
    return 1;
  }
  if (!storage.initSchema(message)) {
    fprintf(stderr, "nta: %s\n", message.c_str());
    return 1;
  }
  const std::vector<std::string> &pos = cli.positionals();
  if (pos.size() < 2) {
    fprintf(stderr, "nta: analyze needs at least one pcap file\n");
    return 1;
  }

  std::vector<Conversation> allConvs;
  std::map<std::string, int64_t> subjectToConversation;
  std::map<std::string, int64_t> subjectToCapture;
  bool anyFileFailed = false;

  for (size_t i = 1; i < pos.size(); i++) {
    const std::string &path = pos[i];
    PcapFileReader reader;
    std::string openErr = reader.open(path);
    if (!openErr.empty()) {
      fprintf(stderr, "nta: %s\n", openErr.c_str());
      anyFileFailed = true;
      continue;
    }
    CaptureRecord capRec;
    capRec.path = path;
    capRec.fileSize = (int64_t)reader.fileSize();
    ConversationTracker tracker;
    std::vector<PacketStatRecord> pstats;
    PcapFileReader::Packet pkt;
    while (reader.next(pkt)) {
      PacketMetadata m =
          parsePacket(pkt.data.data(), pkt.capturedLen, reader.linkType());
      m.timestampUs = pkt.timestampUs;
      tracker.addPacket(m);
      capRec.packets++;
      capRec.bytes += pkt.capturedLen;
      if (capRec.firstPacketUs == 0) {
        capRec.firstPacketUs = pkt.timestampUs;
      }
      capRec.lastPacketUs = pkt.timestampUs;
      if (m.hasIp) {
        PacketStatRecord p;
        p.timestampUs = pkt.timestampUs;
        p.protocol = m.ipProtocol;
        p.srcIp = m.srcIp.text();
        p.dstIp = m.dstIp.text();
        if (m.hasTcp) {
          p.srcPort = m.tcpSrcPort;
          p.dstPort = m.tcpDstPort;
        } else if (m.hasUdp) {
          p.srcPort = m.udpSrcPort;
          p.dstPort = m.udpDstPort;
        }
        p.bytes = pkt.capturedLen;
        pstats.push_back(p);
      }
    }
    std::string readErr = reader.lastError();
    if (!readErr.empty()) {
      fprintf(stderr, "nta: warning: %s\n", readErr.c_str());
    }

    std::vector<Conversation> convs = tracker.finish();
    allConvs.insert(allConvs.end(), convs.begin(), convs.end());

    if (!storage.insertCapture(capRec, message)) {
      fprintf(stderr, "nta: %s\n", message.c_str());
      return 1;
    }
    for (auto &p : pstats) {
      p.captureId = capRec.id;
    }
    if (!storage.insertPackets(pstats, message)) {
      fprintf(stderr, "nta: %s\n", message.c_str());
      return 1;
    }

    std::vector<HostRecord> hosts = aggregateHosts(convs, tracker.hostMacs);
    if (!storage.insertHosts(hosts, message)) {
      fprintf(stderr, "nta: %s\n", message.c_str());
      return 1;
    }
    std::map<std::string, int64_t> hostIds;
    for (const HostRecord &h : hosts) {
      int64_t id = 0;
      if (storage.findHostId(h.ip, id, message)) {
        hostIds[h.ip] = id;
      }
    }

    std::vector<ConversationRecord> convRecs;
    for (const Conversation &c : convs) {
      convRecs.push_back(toConversationRecord(
          c, capRec.id, hostIds[c.key.srcIp], hostIds[c.key.dstIp]));
    }
    if (!storage.insertConversations(convRecs, message)) {
      fprintf(stderr, "nta: %s\n", message.c_str());
      return 1;
    }
    for (const ConversationRecord &r : convRecs) {
      subjectToConversation[describeConversationKey(r)] = r.id;
      subjectToCapture[describeConversationKey(r)] = r.captureId;
    }

    std::vector<DnsQueryRecord> dns;
    for (size_t j = 0; j < convs.size(); j++) {
      const Conversation &c = convs[j];
      for (const DnsQueryEvent &q : c.dnsQueries) {
        DnsQueryRecord d;
        d.conversationId = convRecs[j].id;
        d.captureId = capRec.id;
        d.host = c.key.srcIp;
        d.name = q.name;
        d.qtype = q.qtype;
        d.typeName = q.typeName;
        d.timestampUs = q.timestampUs;
        d.isResponse = q.isResponse;
        d.rcode = q.rcode;
        d.answers = q.answers;
        dns.push_back(d);
      }
    }
    if (!storage.insertDnsQueries(dns, message)) {
      fprintf(stderr, "nta: %s\n", message.c_str());
      return 1;
    }

    std::vector<HttpEventRecord> http;
    for (size_t j = 0; j < convs.size(); j++) {
      const Conversation &c = convs[j];
      int64_t convId = convRecs[j].id;
      for (const HttpRequest &r : c.http.requests) {
        HttpEventRecord e;
        e.conversationId = convId;
        e.captureId = capRec.id;
        e.host = c.key.srcIp;
        e.kind = "request";
        e.method = r.method;
        e.path = r.target;
        e.hostHeader = r.hostHeader;
        e.userAgent = r.userAgent;
        e.referer = r.referer;
        e.contentType = r.contentType;
        e.status = 0;
        e.timestampUs = c.firstPacketUs;
        http.push_back(e);
      }
      for (const HttpResponse &r : c.http.responses) {
        HttpEventRecord e;
        e.conversationId = convId;
        e.captureId = capRec.id;
        e.host = c.key.dstIp;
        e.kind = "response";
        e.status = r.status;
        e.contentType = r.contentType;
        e.server = r.server;
        e.location = r.location;
        e.timestampUs = c.lastPacketUs;
        http.push_back(e);
      }
    }
    if (!storage.insertHttpEvents(http, message)) {
      fprintf(stderr, "nta: %s\n", message.c_str());
      return 1;
    }

    printf("analyzed %s: %lld packets, %lld bytes, %lld conversations, %lld "
           "hosts\n",
           path.c_str(), (long long)capRec.packets, (long long)capRec.bytes,
           (long long)convs.size(), (long long)hosts.size());
  }

  std::vector<AnomalyRecord> anomalies = detectAnomalies(allConvs);
  for (AnomalyRecord &a : anomalies) {
    auto it = subjectToConversation.find(a.subject);
    if (it != subjectToConversation.end()) {
      a.conversationId = it->second;
      a.captureId = subjectToCapture[a.subject];
    }
  }
  if (!storage.insertAnomalies(anomalies, message)) {
    fprintf(stderr, "nta: %s\n", message.c_str());
    return 1;
  }
  printf("detected %zu anomalies\n", anomalies.size());
  return anyFileFailed ? 1 : 0;
}

// ---------------------------------------------------------------------------
// hosts

int cmdHosts(Storage &storage, const Cli &cli, std::string &message) {
  if (!openStorage(storage, cli, message)) {
    return 1;
  }
  std::vector<HostRecord> hosts;
  if (!storage.listHosts(cli.get("host", ""), hosts, message)) {
    fprintf(stderr, "nta: %s\n", message.c_str());
    return 1;
  }
  printf("HOSTS (%zu)\n", hosts.size());
  printf("%-3s %-18s %-21s %10s %12s %12s %-22s %-22s\n", "id", "ip", "mac",
         "packets", "bytesSent", "bytesRecv", "firstSeen", "lastSeen");
  for (const HostRecord &h : hosts) {
    printf("%-3lld %-18s %-21s %10llu %12llu %12llu %-22s %-22s\n",
           (long long)h.id, h.ip.c_str(), h.mac.c_str(),
           (unsigned long long)h.packetCount, (unsigned long long)h.bytesSent,
           (unsigned long long)h.bytesReceived,
           formatTimestamp(h.firstSeenUs).c_str(),
           formatTimestamp(h.lastSeenUs).c_str());
  }
  return 0;
}

// ---------------------------------------------------------------------------
// conversations

int cmdConversations(Storage &storage, const Cli &cli, std::string &message) {
  if (!openStorage(storage, cli, message)) {
    return 1;
  }
  std::vector<ConversationRecord> convs;
  int limit = cli.getInt("limit", 50);
  if (!storage.listConversations(cli.get("protocol", ""), cli.get("host", ""),
                                 limit, convs, message)) {
    fprintf(stderr, "nta: %s\n", message.c_str());
    return 1;
  }
  printf("CONVERSATIONS (%zu)\n", convs.size());
  for (const ConversationRecord &c : convs) {
    printf(
        "%-3lld %s:%u -> %s:%u [%s] pkts=%llu bytes=%llu payload=%llu %s -> %s",
        (long long)c.id, c.srcIp.c_str(), (unsigned)c.srcPort, c.dstIp.c_str(),
        (unsigned)c.dstPort, protocolName(c.protocol).c_str(),
        (unsigned long long)c.packetCount, (unsigned long long)c.totalBytes,
        (unsigned long long)c.totalPayloadBytes,
        formatTimestamp(c.startUs).c_str(), formatTimestamp(c.endUs).c_str());
    if (c.isDns) {
      printf(" dns=%s", c.dnsQueryName.c_str());
    }
    if (c.isHttp) {
      printf(" http(r=%d,x=%d)", c.httpRequests, c.httpResponses);
    }
    printf("\n");
  }
  return 0;
}

// ---------------------------------------------------------------------------
// timeline

int cmdTimeline(Storage &storage, const Cli &cli, std::string &message) {
  if (!openStorage(storage, cli, message)) {
    return 1;
  }
  int64_t sinceUs = -1;
  int64_t untilUs = -1;
  if (cli.has("since")) {
    sinceUs = (int64_t)(cli.getDouble("since", 0) * 1000000.0);
  }
  if (cli.has("until")) {
    untilUs = (int64_t)(cli.getDouble("until", 0) * 1000000.0);
  }
  std::vector<TimelineEntry> entries =
      buildTimeline(storage, sinceUs, untilUs, cli.get("host", ""));
  int limit = cli.getInt("limit", 0);
  if (limit > 0 && entries.size() > (size_t)limit) {
    entries.resize((size_t)limit);
  }
  printf("TIMELINE (%zu entries)\n", entries.size());
  for (const TimelineEntry &e : entries) {
    printf("%s [%-14s] %-22s %s\n", formatTimestamp(e.timestampUs).c_str(),
           e.kind.c_str(), e.host.c_str(), e.detail.c_str());
  }
  return 0;
}

// ---------------------------------------------------------------------------
// dns

int cmdDns(Storage &storage, const Cli &cli, std::string &message) {
  if (!openStorage(storage, cli, message)) {
    return 1;
  }
  std::vector<DnsQueryRecord> qs;
  if (!storage.listDnsQueries(cli.get("host", ""), cli.getInt("limit", 100), qs,
                              message)) {
    fprintf(stderr, "nta: %s\n", message.c_str());
    return 1;
  }
  printf("DNS QUERIES (%zu)\n", qs.size());
  for (const DnsQueryRecord &q : qs) {
    printf("%s %-16s %-42s %s", formatTimestamp(q.timestampUs).c_str(),
           q.host.c_str(), q.name.c_str(), q.typeName.c_str());
    if (q.isResponse) {
      std::string answers;
      for (const std::string &a : q.answers) {
        if (!answers.empty()) {
          answers += "; ";
        }
        answers += a;
      }
      printf(" response rcode=%d answers=[%s]", q.rcode, answers.c_str());
    }
    printf("\n");
  }
  return 0;
}

// ---------------------------------------------------------------------------
// anomalies

int cmdAnomalies(Storage &storage, const Cli &cli, std::string &message) {
  if (!openStorage(storage, cli, message)) {
    return 1;
  }
  std::vector<AnomalyRecord> ans;
  if (!storage.listAnomalies(cli.getDouble("min-conf", 0), cli.get("type", ""),
                             ans, message)) {
    fprintf(stderr, "nta: %s\n", message.c_str());
    return 1;
  }
  printf("ANOMALIES (%zu)\n", ans.size());
  for (const AnomalyRecord &a : ans) {
    printf("[%6.2f] %-20s %-8s %s\n", a.confidence, a.type.c_str(),
           a.severity.c_str(), a.subject.c_str());
    if (!a.evidence.empty()) {
      printf("        evidence: %s\n", a.evidence.c_str());
    }
    if (!a.explanation.empty()) {
      printf("        why: %s\n", a.explanation.c_str());
    }
  }
  return 0;
}

// ---------------------------------------------------------------------------
// stats

int cmdStats(const Cli &cli, std::string &message) {
  std::string dbPath = cli.get("db", defaultDbPath());
  return runPythonStats(dbPath, cli.get("out", ""), message);
}

// ---------------------------------------------------------------------------
// report

int cmdReport(Storage &storage, const Cli &cli, std::string &message) {
  int rc = cmdHosts(storage, cli, message);
  printf("\n");
  if (cmdConversations(storage, cli, message) != 0) {
    rc = 1;
  }
  printf("\n");
  if (cmdAnomalies(storage, cli, message) != 0) {
    rc = 1;
  }
  printf("\n");
  if (cmdTimeline(storage, cli, message) != 0) {
    rc = 1;
  }
  printf("\n");
  if (cmdStats(cli, message) != 0) {
    rc = 1;
  }
  return rc;
}

// ---------------------------------------------------------------------------
// correlate

int cmdCorrelate(Storage &storage, const Cli &cli, std::string &message) {
  if (!openStorage(storage, cli, message)) {
    return 1;
  }
  std::vector<std::string> lines = buildCorrelationReport(storage);
  for (const std::string &l : lines) {
    printf("%s\n", l.c_str());
  }
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  Cli cli;
  std::string message;
  if (!cli.parse(argc, argv, message)) {
    fprintf(stderr, "nta: %s\n", message.c_str());
    return 2;
  }
  if (cli.has("version")) {
    printf("%s\n", kVersion);
    return 0;
  }
  const std::vector<std::string> &pos = cli.positionals();
  std::string command = pos.empty() ? "" : pos[0];
  if (cli.has("help") || command.empty()) {
    printf("%s", Cli::usage("nta").c_str());
    return cli.has("help") ? 0 : 2;
  }
  Storage storage;
  if (command == "analyze") {
    return cmdAnalyze(storage, cli, message);
  }
  if (command == "hosts") {
    return cmdHosts(storage, cli, message);
  }
  if (command == "conversations") {
    return cmdConversations(storage, cli, message);
  }
  if (command == "timeline") {
    return cmdTimeline(storage, cli, message);
  }
  if (command == "dns") {
    return cmdDns(storage, cli, message);
  }
  if (command == "anomalies") {
    return cmdAnomalies(storage, cli, message);
  }
  if (command == "stats") {
    return cmdStats(cli, message);
  }
  if (command == "report") {
    return cmdReport(storage, cli, message);
  }
  if (command == "correlate") {
    return cmdCorrelate(storage, cli, message);
  }
  fprintf(stderr, "nta: unknown command '%s'\n\n%s", command.c_str(),
          Cli::usage("nta").c_str());
  return 2;
}
