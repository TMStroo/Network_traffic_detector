#ifndef NTA_PCAP_H
#define NTA_PCAP_H

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

class PcapFileReader {
public:
    struct Packet {
        int64_t timestampUs = 0;
        uint32_t capturedLen = 0;
        uint32_t originalLen = 0;
        std::vector<uint8_t> data;
    };

    PcapFileReader() = default;
    ~PcapFileReader();

    PcapFileReader(const PcapFileReader&) = delete;
    PcapFileReader& operator=(const PcapFileReader&) = delete;

    std::string open(const std::string& path);
    bool next(Packet& out);

    int linkType() const { return linkType_; }
    uint64_t fileSize() const;
    std::string lastError() const { return error_; }

private:
    struct Reader {
        bool invalid = false;
        bool bigEndian = false;
        bool nanoseconds = false;
    };

    Reader readGlobalHeader(const uint8_t* header);
    void close();
    void markError(const std::string& message) { error_ = message; }

    std::string path_;
    std::string error_;
    int linkType_ = 0;
    bool bigEndian_ = false;
    bool nanoseconds_ = false;
    FILE* file_ = nullptr;
};

#endif
