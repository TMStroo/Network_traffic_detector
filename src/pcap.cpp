#include "pcap.h"

#include <sys/stat.h>

namespace {

uint16_t readU16(const uint8_t* p, bool bigEndian) {
    if (bigEndian) {
        return (uint16_t)((p[0] << 8) | p[1]);
    }
    return (uint16_t)(p[0] | (p[1] << 8));
}

uint32_t readU32(const uint8_t* p, bool bigEndian) {
    if (bigEndian) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

}  // namespace

PcapFileReader::Reader PcapFileReader::readGlobalHeader(const uint8_t* header) {
    Reader r;
    r.invalid = true;
    uint32_t magic = readU32(header, false);
    if (magic == 0xa1b2c3d4) {
        r.invalid = false;
        r.bigEndian = false;
        r.nanoseconds = false;
    } else if (magic == 0xa1b23c4d) {
        r.invalid = false;
        r.bigEndian = false;
        r.nanoseconds = true;
    } else if (magic == 0xd4c3b2a1) {
        r.invalid = false;
        r.bigEndian = true;
        r.nanoseconds = false;
    } else if (magic == 0x4d3cb2a1) {
        r.invalid = false;
        r.bigEndian = true;
        r.nanoseconds = true;
    }
    return r;
}

std::string PcapFileReader::open(const std::string& path) {
    path_ = path;
    error_.clear();
    file_ = fopen(path.c_str(), "rb");
    if (!file_) {
        markError("cannot open file: " + path);
        isOpen_ = false;
        return error_;
    }
    uint8_t header[24];
    size_t got = fread(header, 1, sizeof(header), file_);
    if (got != sizeof(header)) {
        markError("truncated global header in: " + path);
        fclose(file_);
        file_ = nullptr;
        isOpen_ = false;
        return error_;
    }
    Reader r = readGlobalHeader(header);
    if (r.invalid) {
        markError("not a classic pcap file: " + path);
        fclose(file_);
        file_ = nullptr;
        isOpen_ = false;
        return error_;
    }
    bigEndian_ = r.bigEndian;
    nanoseconds_ = r.nanoseconds;
    uint16_t major = readU16(header + 4, bigEndian_);
    uint16_t minor = readU16(header + 6, bigEndian_);
    (void)major;
    (void)minor;
    linkType_ = (int)readU32(header + 20, bigEndian_);
    isOpen_ = true;
    error_.clear();
    return error_;
}

bool PcapFileReader::next(Packet& out) {
    if (!file_) {
        return false;
    }
    uint8_t rec[16];
    size_t got = fread(rec, 1, sizeof(rec), file_);
    if (got == 0) {
        return false;  // clean EOF
    }
    if (got != sizeof(rec)) {
        markError("truncated packet record in: " + path_);
        return false;
    }
    uint32_t sec = readU32(rec + 0, bigEndian_);
    uint32_t frac = readU32(rec + 4, bigEndian_);
    uint32_t capturedLen = readU32(rec + 8, bigEndian_);
    uint32_t originalLen = readU32(rec + 12, bigEndian_);
    if (capturedLen > 32 * 1024 * 1024) {
        markError("packet record too large in: " + path_);
        return false;
    }
    out.data.resize(capturedLen);
    if (capturedLen > 0) {
        size_t want = fread(out.data.data(), 1, capturedLen, file_);
        if (want != capturedLen) {
            markError("truncated packet data in: " + path_);
            return false;
        }
    }
    out.timestampUs = (int64_t)sec * 1000000LL +
                      (nanoseconds_ ? (int64_t)frac / 1000 : (int64_t)frac);
    out.capturedLen = capturedLen;
    out.originalLen = originalLen;
    return true;
}

uint64_t PcapFileReader::fileSize() const {
    struct stat st;
    if (stat(path_.c_str(), &st) != 0) {
        return 0;
    }
    return (uint64_t)st.st_size;
}
