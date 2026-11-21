#include "python_stats.h"

#include <cstdio>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

bool fileExists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

// Finds python/nta_stats.py relative to the running executable.
// Input: none.
// Output: path to the statistics module.
std::string findStatsScript() {
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        std::string exe(buf);
        size_t slash = exe.find_last_of('/');
        if (slash != std::string::npos) {
            std::string base = exe.substr(0, slash + 1);
            if (fileExists(base + "../python/nta_stats.py")) {
                return base + "../python/nta_stats.py";
            }
            if (fileExists(base + "nta_stats.py")) {
                return base + "nta_stats.py";
            }
        }
    }
    if (fileExists("python/nta_stats.py")) {
        return "python/nta_stats.py";
    }
    return "nta_stats.py";
}

}  // namespace

int runPythonStats(const std::string& dbPath, const std::string& outFile,
                   std::string& message) {
    std::string script = findStatsScript();
    std::string cmd = "python3 \"" + script + "\" --db \"" + dbPath + "\"";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        message = "could not start python3";
        return 1;
    }
    FILE* out = stdout;
    if (!outFile.empty()) {
        out = fopen(outFile.c_str(), "w");
        if (!out) {
            message = "cannot open output file: " + outFile;
            pclose(pipe);
            return 1;
        }
    }
    char line[1024];
    while (fgets(line, sizeof(line), pipe)) {
        fputs(line, out);
    }
    int status = pclose(pipe);
    if (out != stdout) {
        fclose(out);
    }
    if (status != 0) {
        message = "python3 statistics module exited with status " +
                  std::to_string(status);
        return 1;
    }
    return 0;
}
