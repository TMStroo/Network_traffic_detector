#include "pcap.h"

#include <sys/stat.h>

namespace {

uint16_t readU16(const uint8_t* p, bool bigEndian) {
    if (bigEndian) {
        return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
    }
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

uint32_t readU32(const uint8_t* p, bool bigEndian) {
    if (bigEndian) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

}

PcapFileReader::~PcapFileReader() {
    close();
}

void PcapFileReader::close() {
    if (file_) {
        fclose(file_);
        file_ = nullptr;
    }
}

PcapFileReader::Reader PcapFileReader::readGlobalHeader(const uint8_t* header) {
    Reader reader;
    reader.invalid = true;

    uint32_t magic = readU32(header, false);

    if (magic == 0xa1b2c3d4) {
        reader.invalid = false;
    } else if (magic == 0xa1b23c4d) {
        reader.invalid = false;
        reader.nanoseconds = true;
    } else if (magic == 0xd4c3b2a1) {
        reader.invalid = false;
        reader.bigEndian = true;
    } else if (magic == 0x4d3cb2a1) {
        reader.invalid = false;
        reader.bigEndian = true;
        reader.nanoseconds = true;
    }

    return reader;
}

std::string PcapFileReader::open(const std::string& path) {
    close();
    path_ = path;
    error_.clear();
    linkType_ = 0;

    file_ = fopen(path.c_str(), "rb");
    if (!file_) {
        markError("cannot open file: " + path);
        return error_;
    }

    uint8_t header[24];
    size_t got = fread(header, 1, sizeof(header), file_);

    if (got != sizeof(header)) {
        markError("truncated global header in: " + path);
        close();
        return error_;
    }

    Reader reader = readGlobalHeader(header);
    if (reader.invalid) {
        markError("not a classic pcap file: " + path);
        close();
        return error_;
    }

    bigEndian_ = reader.bigEndian;
    nanoseconds_ = reader.nanoseconds;
    linkType_ = (int)readU32(header + 20, bigEndian_);

    return error_;
}

bool PcapFileReader::next(Packet& out) {
    if (!file_) {
        return false;
    }

    uint8_t record[16];
    size_t got = fread(record, 1, sizeof(record), file_);

    if (got == 0) {
        if (ferror(file_)) {
            markError("failed while reading: " + path_);
        }
        return false;
    }

    if (got != sizeof(record)) {
        markError("truncated packet record in: " + path_);
        return false;
    }

    uint32_t seconds = readU32(record, bigEndian_);
    uint32_t fraction = readU32(record + 4, bigEndian_);
    uint32_t capturedLength = readU32(record + 8, bigEndian_);
    uint32_t originalLength = readU32(record + 12, bigEndian_);

    if (capturedLength > 32 * 1024 * 1024 || capturedLength > originalLength) {
        markError("invalid packet length in: " + path_);
        return false;
    }

    out.data.resize(capturedLength);

    if (capturedLength > 0) {
        size_t packetBytes = fread(out.data.data(), 1, capturedLength, file_);
        if (packetBytes != capturedLength) {
            markError("truncated packet data in: " + path_);
            return false;
        }
    }

    out.timestampUs = (int64_t)seconds * 1000000LL +
                      (nanoseconds_ ? (int64_t)fraction / 1000 : fraction);
    out.capturedLen = capturedLength;
    out.originalLen = originalLength;

    return true;
}

uint64_t PcapFileReader::fileSize() const {
    struct stat fileInfo;
    if (stat(path_.c_str(), &fileInfo) != 0) {
        return 0;
    }
    return (uint64_t)fileInfo.st_size;
}
