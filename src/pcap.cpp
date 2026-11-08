#include "pcap.hpp"
#include <fstream>

namespace pcap {

static uint32_t rd32(const uint8_t* p, bool swap) {
    uint32_t v = uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    if (!swap) return v;
    return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | (v >> 24);
}

bool readFile(const std::string& path, std::vector<Packet>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    uint8_t gh[24];
    if (!f.read(reinterpret_cast<char*>(gh), 24)) return false;

    const uint32_t magic = rd32(gh, false);
    bool swap;
    if (magic == 0xa1b2c3d4) swap = false;
    else if (magic == 0xd4c3b2a1) swap = true;
    else return false;                           // not a classic pcap
    if (rd32(gh + 20, swap) != 1) return false;  // Ethernet only

    uint8_t ph[16];
    while (f.read(reinterpret_cast<char*>(ph), 16)) {
        const uint32_t caplen = rd32(ph + 8, swap);
        if (caplen > (1u << 24)) return false;   // sanity limit
        Packet p(caplen);
        if (!f.read(reinterpret_cast<char*>(p.data()), caplen)) return false;
        out.push_back(std::move(p));
    }
    return true;
}

std::optional<Span> extractGtpu(const uint8_t* d, size_t len) {
    if (len < 14) return std::nullopt;
    size_t off = 12;
    uint16_t ethertype = uint16_t((d[off] << 8) | d[off + 1]);
    off += 2;
    if (ethertype == 0x8100) {                   // single VLAN tag
        if (len < off + 4) return std::nullopt;
        ethertype = uint16_t((d[off + 2] << 8) | d[off + 3]);
        off += 4;
    }
    if (ethertype != 0x0800) return std::nullopt;          // IPv4 only
    if (len < off + 20) return std::nullopt;
    const size_t ihl = size_t(d[off] & 0x0f) * 4;
    if ((d[off] >> 4) != 4 || ihl < 20 || len < off + ihl + 8) return std::nullopt;
    if (d[off + 9] != 17) return std::nullopt;             // UDP only
    const size_t udp = off + ihl;
    const uint16_t sport = uint16_t((d[udp] << 8) | d[udp + 1]);
    const uint16_t dport = uint16_t((d[udp + 2] << 8) | d[udp + 3]);
    if (sport != 2152 && dport != 2152) return std::nullopt;
    return Span{d + udp + 8, len - (udp + 8)};
}

}  // namespace pcap
