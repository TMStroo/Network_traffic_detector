#include "cli.h"

#include <cstdlib>

namespace {

// Switches that never take a value.
const std::set<std::string> kBooleanSwitches = {"help", "version", "reset"};

} // namespace

bool Cli::parse(int argc, char **argv, std::string &message) {
  message.clear();
  int i = 1;
  while (i < argc) {
    std::string tok = argv[i];
    if (tok.size() > 1 && tok[0] == '-') {
      std::string body = tok;
      while (!body.empty() && body[0] == '-') {
        body.erase(body.begin());
      }
      std::string name = body;
      std::string value;
      bool hasValue = false;
      size_t eq = body.find('=');
      if (eq != std::string::npos) {
        name = body.substr(0, eq);
        value = body.substr(eq + 1);
        hasValue = true;
      }
      if (!kBooleanSwitches.count(name) && !hasValue && i + 1 < argc) {
        std::string next = argv[i + 1];
        if (next.size() > 1 && next[0] != '-') {
          value = next;
          hasValue = true;
          i++;
        }
      }
      Opt o;
      o.name = name;
      o.value = value;
      o.hasValue = hasValue;
      opts_.push_back(o);
    } else {
      positional_.push_back(tok);
    }
    i++;
  }
  return true;
}

bool Cli::value(const std::string &name, std::string &out) const {
  for (const Opt &o : opts_) {
    if (o.name == name && o.hasValue) {
      out = o.value;
      return true;
    }
  }
  return false;
}

std::string Cli::get(const std::string &name,
                     const std::string &defaultValue) const {
  std::string v;
  if (value(name, v)) {
    return v;
  }
  return defaultValue;
}

int Cli::getInt(const std::string &name, int defaultValue) const {
  std::string v;
  if (value(name, v)) {
    return atoi(v.c_str());
  }
  return defaultValue;
}

double Cli::getDouble(const std::string &name, double defaultValue) const {
  std::string v;
  if (value(name, v)) {
    return atof(v.c_str());
  }
  return defaultValue;
}

bool Cli::getBool(const std::string &name, bool defaultValue) const {
  for (const Opt &o : opts_) {
    if (o.name == name) {
      return true;
    }
  }
  return defaultValue;
}

bool Cli::has(const std::string &name) const {
  for (const Opt &o : opts_) {
    if (o.name == name) {
      return true;
    }
  }
  return false;
}

std::string Cli::usage(const std::string &programName) {
  return std::string(
      "Usage: " + programName +
      " <command> [options]\n"
      "\n"
      "Commands:\n"
      "  analyze <pcap> [<pcap>...]  Read PCAP files; store packets, "
      "conversations,\n"
      "                              DNS, HTTP, host and anomaly data\n"
      "      --db PATH               Database file (default \"analyze.db\")\n"
      "      --reset                 Delete the database before analyzing\n"
      "  hosts                       List hosts\n"
      "      --host FILTER           Filter by host name or substring\n"
      "  conversations               List reconstructed conversations\n"
      "      --protocol tcp|udp      Filter by protocol\n"
      "      --host FILTER           Filter by host name or substring\n"
      "      --limit N               Max rows to print\n"
      "  timeline                    Print the activity timeline\n"
      "      --host FILTER           Filter by host name or substring\n"
      "      --since TS              Only entries at or after this Unix time "
      "(seconds)\n"
      "      --until TS              Only entries at or before this Unix time "
      "(seconds)\n"
      "      --limit N               Max entries to print\n"
      "  dns                         List DNS queries and responses\n"
      "      --host FILTER           Filter by host name or substring\n"
      "      --limit N               Max rows to print\n"
      "  anomalies                   List detected anomalies\n"
      "      --type TYPE             Filter by anomaly type (e.g. beaconing)\n"
      "      --min-conf X            Minimum confidence (0-1)\n"
      "  stats                       Statistical summary (Python module)\n"
      "  report                      Full report: hosts, conversations, "
      "anomalies,\n"
      "                              timeline and statistics\n"
      "  correlate                   Cross-capture correlation summary\n"
      "\n"
      "General options:\n"
      "  --db PATH     Database file (default \"analyze.db\"; $NTA_DB also "
      "works)\n"
      "  --help        Show this help\n"
      "  --version     Show version\n");
}
