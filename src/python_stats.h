#ifndef NTA_PYTHON_STATS_H
#define NTA_PYTHON_STATS_H

#include <string>

// Runs the Python statistics module against the analysis database.
// Input: database path, optional output file for the JSON report ("" = stdout).
// Output: returns 0 on success, nonzero on failure; message holds the error.
int runPythonStats(const std::string& dbPath, const std::string& outFile,
                   std::string& message);

#endif
