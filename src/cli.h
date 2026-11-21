#ifndef NTA_CLI_H
#define NTA_CLI_H

#include <set>
#include <string>
#include <vector>

// Parses command line arguments into "--name value" switches and positional
// values. Boolean switches never consume the following token.
class Cli {
public:
    // Input: argc and argv as passed to main.
    // Output: true always; message is empty when parsing succeeded.
    bool parse(int argc, char** argv, std::string& message);

    // Input: switch name without dashes.
    // Output: true and fills out when the switch was passed with a value.
    bool value(const std::string& name, std::string& out) const;

    // Input: switch name, default when absent or without value.
    std::string get(const std::string& name, const std::string& defaultValue) const;

    // Input: switch name, default when absent.
    int getInt(const std::string& name, int defaultValue) const;

    // Input: switch name, default when absent.
    double getDouble(const std::string& name, double defaultValue) const;

    // Input: switch name, default when absent.
    bool getBool(const std::string& name, bool defaultValue) const;

    // Input: switch name.
    // Output: true when the switch was passed.
    bool has(const std::string& name) const;

    // Input: none.
    // Output: positional arguments (values that are not switches).
    const std::vector<std::string>& positionals() const { return positional_; }

    // Input: program name.
    // Output: usage text.
    static std::string usage(const std::string& programName);

private:
    struct Opt {
        std::string name;
        std::string value;
        bool hasValue = false;
    };
    std::vector<Opt> opts_;
    std::vector<std::string> positional_;
};

#endif
