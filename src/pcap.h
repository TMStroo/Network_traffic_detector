#ifndef NTA_PCAP_H
#define NTA_PCAP_H

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

// Reads packets from a classic libpcap capture file.
class PcapFileReader {
public:
    struct Packet {
        int64_t timestampUs = 0;   // microseconds since the Unix epoch
        uint32_t capturedLen = 0;  // bytes stored in this packet record
        uint32_t originalLen = 0; // bytes on the wire
        std::vector<uint8_t> data; // captured bytes
    };

    // Opens the file and reads the global header.
    // Input: path of the pcap file.
    // Output: empty string on success, or an error message.
    std::string open(const std::string& path);

    // Reads the next packet record.
    // Input: none.
    // Output: returns true and fills out when a record exists; returns false at EOF.
    bool next(Packet& out);

    // Returns the link type from the capture header (1 = Ethernet).
    // Input: none.
    // Output: integer link type value.
    int linkType() const { return linkType_; }

    // Returns the size of the file in bytes, or 0 if it could not be read.
    // Input: none.
    // Output: file size in bytes.
    uint64_t fileSize() const;

    // Returns the last error seen, or an empty string when the reader is usable.
    // Input: none.
    // Output: error string, empty if no error.
    std::string lastError() const { return error_; }

private:
    struct Reader {
        bool invalid = false;
        bool bigEndian = false;
        bool nanoseconds = false;
    };

    Reader readGlobalHeader(const uint8_t* header);

    void markError(const std::string& message) { error_ = message; }

    bool isOpen_ = false;
    std::string path_;
    std::string error_;
    int linkType_ = 0;
    bool bigEndian_ = false;
    bool nanoseconds_ = false;
    FILE* file_ = nullptr;
};

#endif
