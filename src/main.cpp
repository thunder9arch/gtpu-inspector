#include <cstdio>
#include <cstdlib>
#include <map>
#include <optional>
#include <string>
#include "filter.hpp"
#include "gtpu.hpp"
#include "pcap.hpp"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <file.pcap> [--teid <n|0xHEX>] [--sample N]\n", argv[0]);
        return 1;
    }
    std::optional<uint32_t> teid;
    uint32_t sample = 1;
    for (int i = 2; i + 1 < argc; i += 2) {
        std::string k = argv[i];
        if (k == "--teid") teid = uint32_t(std::strtoul(argv[i + 1], nullptr, 0));
        else if (k == "--sample") sample = uint32_t(std::strtoul(argv[i + 1], nullptr, 0));
    }

    std::vector<pcap::Packet> packets;
    if (!pcap::readFile(argv[1], packets)) {
        std::fprintf(stderr, "could not read %s as classic pcap (Ethernet)\n", argv[1]);
        return 1;
    }

    Filter filter(teid, sample);
    std::map<uint32_t, unsigned> perTeid;
    unsigned total = 0, gtp = 0, malformed = 0, kept = 0;

    for (const auto& p : packets) {
        ++total;
        auto span = pcap::extractGtpu(p.data(), p.size());
        if (!span) continue;
        auto h = gtpu::parse(span->data, span->len);
        if (!h) { ++malformed; continue; }
        ++gtp;
        if (!filter.accept(*h)) continue;
        ++kept;
        ++perTeid[h->teid];
        std::printf("pkt %u: TEID=0x%08x msg=%u len=%u hdr=%zu\n",
                    total, h->teid, h->messageType, h->length, h->headerLen);
    }

    std::printf("\ntotal=%u gtp-u=%u malformed=%u kept=%u\n", total, gtp, malformed, kept);
    for (const auto& [t, c] : perTeid) std::printf("  TEID 0x%08x -> %u packets\n", t, c);
    return 0;
}
