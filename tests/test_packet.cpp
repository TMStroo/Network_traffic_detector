#include "packet.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

void write16(std::vector<uint8_t>& data, size_t offset, uint16_t value) {
    data[offset] = (uint8_t)(value >> 8);
    data[offset + 1] = (uint8_t)value;
}

std::vector<uint8_t> ethernetFrame(uint16_t etherType) {
    std::vector<uint8_t> frame(14, 0);
    write16(frame, 12, etherType);
    return frame;
}

std::vector<uint8_t> ipv4Frame(uint8_t protocol,
                               const std::vector<uint8_t>& transport,
                               uint16_t fragment = 0) {
    std::vector<uint8_t> frame = ethernetFrame(0x0800);
    size_t start = frame.size();
    frame.resize(start + 20 + transport.size(), 0);
    frame[start] = 0x45;
    write16(frame, start + 2, (uint16_t)(20 + transport.size()));
    write16(frame, start + 6, fragment);
    frame[start + 8] = 64;
    frame[start + 9] = protocol;
    frame[start + 12] = 10;
    frame[start + 15] = 5;
    frame[start + 16] = 8;
    frame[start + 19] = 8;
    for (size_t i = 0; i < transport.size(); i++) {
        frame[start + 20 + i] = transport[i];
    }
    return frame;
}

std::vector<uint8_t> tcpHeader(uint8_t dataOffset) {
    std::vector<uint8_t> tcp(20, 0);
    write16(tcp, 0, 40000);
    write16(tcp, 2, 443);
    tcp[12] = (uint8_t)(dataOffset << 4);
    tcp[13] = 0x02;
    return tcp;
}

std::vector<uint8_t> udpHeader(uint16_t length) {
    std::vector<uint8_t> udp(8, 0);
    write16(udp, 0, 40000);
    write16(udp, 2, 53);
    write16(udp, 4, length);
    return udp;
}

void testValidTcp() {
    auto frame = ipv4Frame(6, tcpHeader(5));
    PacketMetadata packet = parsePacket(frame.data(), frame.size(), 1);
    assert(packet.hasIp);
    assert(packet.hasTcp);
    assert(packet.syn);
}

void testInvalidTcpHeaderLength() {
    auto frame = ipv4Frame(6, tcpHeader(4));
    PacketMetadata packet = parsePacket(frame.data(), frame.size(), 1);
    assert(packet.hasIp);
    assert(!packet.hasTcp);
}

void testInvalidUdpLength() {
    auto frame = ipv4Frame(17, udpHeader(7));
    PacketMetadata packet = parsePacket(frame.data(), frame.size(), 1);
    assert(packet.hasIp);
    assert(!packet.hasUdp);
}

void testIpv4FragmentIsNotParsedAsTransport() {
    auto frame = ipv4Frame(6, tcpHeader(5), 0x2000);
    PacketMetadata packet = parsePacket(frame.data(), frame.size(), 1);
    assert(packet.hasIp);
    assert(packet.isFragment);
    assert(!packet.hasTcp);
}

void testIpv6ExtensionHeader() {
    auto frame = ethernetFrame(0x86DD);
    size_t start = frame.size();
    frame.resize(start + 40 + 8 + 8, 0);
    frame[start] = 0x60;
    write16(frame, start + 4, 16);
    frame[start + 6] = 60;
    frame[start + 8] = 0x20;
    frame[start + 24] = 0x20;

    size_t extension = start + 40;
    frame[extension] = 17;
    frame[extension + 1] = 0;

    size_t udp = extension + 8;
    write16(frame, udp, 40000);
    write16(frame, udp + 2, 53);
    write16(frame, udp + 4, 8);

    PacketMetadata packet = parsePacket(frame.data(), frame.size(), 1);
    assert(packet.hasIp);
    assert(packet.isIpv6);
    assert(packet.hasUdp);
}

}  // namespace

int main() {
    testValidTcp();
    testInvalidTcpHeaderLength();
    testInvalidUdpLength();
    testIpv4FragmentIsNotParsedAsTransport();
    testIpv6ExtensionHeader();
    std::cout << "Packet parser tests passed\n";
    return 0;
}
