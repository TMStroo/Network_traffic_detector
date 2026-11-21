#ifndef NTA_DETECTOR_H
#define NTA_DETECTOR_H

#include "conversation.h"
#include "storage.h"

#include <vector>

// Detects unusual communication patterns across a set of conversations.
// Input: conversations to analyze (already rebuilt by ConversationTracker).
// Output: anomalies with type, severity, subject, evidence, explanation,
//         confidence and event counts.
std::vector<AnomalyRecord> detectAnomalies(const std::vector<Conversation>& convs);

#endif
