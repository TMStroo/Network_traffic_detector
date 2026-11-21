#ifndef NTA_TIMELINE_H
#define NTA_TIMELINE_H

#include "storage.h"

#include <string>
#include <vector>

struct TimelineEntry {
    int64_t timestampUs = 0;
    int64_t captureId = 0;
    std::string kind;   // tcp_session, udp_flow, dns_query, dns_response,
                        // http_request, http_response, anomaly
    std::string host;   // host most relevant to the event
    std::string detail;
};

// Builds the activity timeline from stored conversations, DNS queries, HTTP
// events and anomalies.
// Input: storage to query, optional time window (-1 = unbounded), optional
//        host filter (substring match, empty = all).
// Output: timeline entries sorted by timestamp.
std::vector<TimelineEntry> buildTimeline(Storage& storage, int64_t sinceUs, int64_t untilUs,
                                         const std::string& hostFilter);

// Formats a microsecond timestamp for display.
// Input: microseconds since the Unix epoch.
// Output: string like "2026-11-21T10:23:45Z" in UTC.
std::string formatTimestamp(int64_t tsUs);

#endif
