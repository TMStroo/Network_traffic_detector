#include "pcap.h"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

namespace {

void write32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    bytes[offset] = (uint8_t)value;
    bytes[offset + 1] = (uint8_t)(value >> 8);
    bytes[offset + 2] = (uint8_t)(value >> 16);
    bytes[offset + 3] = (uint8_t)(value >> 24);
}

std::filesystem::path writeCapture(const std::vector<uint8_t>& bytes) {
    auto path = std::filesystem::temp_directory_path() / "nta_reader_test.pcap";
    std::ofstream file(path, std::ios::binary);
    file.write((const char*)bytes.data(), (std::streamsize)bytes.size());
    return path;
}

std::vector<uint8_t> makeHeader() {
    std::vector<uint8_t> bytes(24, 0);
    write32(bytes, 0, 0xa1b2c3d4);
    bytes[4] = 2;
    bytes[6] = 4;
    write32(bytes, 16, 65535);
    write32(bytes, 20, 1);
    return bytes;
}

void testReadsPacket() {
    auto bytes = makeHeader();
    bytes.resize(24 + 16 + 4, 0);
    write32(bytes, 24, 10);
    write32(bytes, 28, 500000);
    write32(bytes, 32, 4);
    write32(bytes, 36, 4);
    bytes[40] = 1;
    bytes[41] = 2;
    bytes[42] = 3;
    bytes[43] = 4;

    auto path = writeCapture(bytes);
    PcapFileReader reader;
    assert(reader.open(path.string()).empty());
    assert(reader.linkType() == 1);

    PcapFileReader::Packet packet;
    assert(reader.next(packet));
    assert(packet.timestampUs == 10500000);
    assert(packet.capturedLen == 4);
    assert(packet.originalLen == 4);
    assert(packet.data.size() == 4);
    assert(packet.data[0] == 1);
    assert(!reader.next(packet));
    assert(reader.lastError().empty());

    std::filesystem::remove(path);
}

void testRejectsTruncatedPacket() {
    auto bytes = makeHeader();
    bytes.resize(24 + 16, 0);
    write32(bytes, 24, 10);
    write32(bytes, 28, 0);
    write32(bytes, 32, 8);
    write32(bytes, 36, 8);

    auto path = writeCapture(bytes);
    PcapFileReader reader;
    assert(reader.open(path.string()).empty());

    PcapFileReader::Packet packet;
    assert(!reader.next(packet));
    assert(!reader.lastError().empty());

    std::filesystem::remove(path);
}

}

int main() {
    testReadsPacket();
    testRejectsTruncatedPacket();
    std::cout << "PCAP reader tests passed\n";
    return 0;
}
