#ifndef NTA_CORRELATOR_H
#define NTA_CORRELATOR_H

#include "storage.h"

#include <string>
#include <vector>

struct CrossCaptureInfo {
    std::string ip;
    int64_t totalPackets = 0;
    int64_t totalPayloadBytes = 0;
    std::vector<std::string> captures;  // capture paths where the host appears
    int anomalyCount = 0;
};

// Builds the cross-capture correlation report.
// Input: storage to query.
// Output: report lines; hosts seen in multiple captures first, then
//         conversation pairs repeated across captures.
std::vector<std::string> buildCorrelationReport(Storage& storage);

#endif
