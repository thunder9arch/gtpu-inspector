#include <cassert>
#include <cstdio>
#include <vector>
#include "../src/filter.hpp"
#include "../src/gtpu.hpp"
#include "../src/pcap.hpp"

using Bytes = std::vector<uint8_t>;

static Bytes gpdu(uint32_t teid, size_t payload = 4) {
    Bytes b = {0x30, 0xff, uint8_t(payload >> 8), uint8_t(payload),
               uint8_t(teid >> 24), uint8_t(teid >> 16), uint8_t(teid >> 8), uint8_t(teid)};
    b.insert(b.end(), payload, 0xAA);
    return b;
}

static void testBasicHeader() {
    auto b = gpdu(0x11223344);
    auto h = gtpu::parse(b.data(), b.size());
    assert(h && h->version == 1 && h->teid == 0x11223344 && h->messageType == 0xff);
    assert(h->length == 4 && h->headerLen == 8);
}

static void testTruncatedAndBadVersion() {
    auto b = gpdu(1, 10);
    assert(!gtpu::parse(b.data(), 5));             // shorter than header
    assert(!gtpu::parse(b.data(), b.size() - 1));  // length field exceeds buffer
    b[0] = 0x50;                                   // version 2
    assert(!gtpu::parse(b.data(), b.size()));
}

static void testOptionalFieldsAndExtension() {
    // flags 0x36 = v1, PT, E+S set. Length 10 = 4 optional + 4 extension + 2 data
    Bytes b = {0x36, 0xff, 0x00, 0x0a, 0, 0, 0, 7,
               0x00, 0x2a, 0x00, 0x85,    // seq=42, npdu=0, next ext type 0x85
               0x01, 0xde, 0xad, 0x00,    // ext: len=1 (4 bytes), content, next=0
               0xBB, 0xBB};
    auto h = gtpu::parse(b.data(), b.size());
    assert(h && h->seq == 42 && h->teid == 7 && h->headerLen == 16);
}

static void testFilterAndSampling() {
    gtpu::Header a; a.teid = 5;
    gtpu::Header other; other.teid = 9;
    Filter f(5u, 3);
    assert(!f.accept(other));
    int kept = 0;
    for (int i = 0; i < 9; ++i) kept += f.accept(a);
    assert(kept == 3);                             // 1 in 3 of 9
}

static void testExtractFromEthernetFrame() {
    Bytes gtp = gpdu(0xCAFE, 2);
    Bytes f(12, 0);                                // MACs
    f.insert(f.end(), {0x08, 0x00});               // IPv4
    f.insert(f.end(), {0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2});
    f.insert(f.end(), {0x08, 0x68, 0x08, 0x68, 0, 0, 0, 0});  // UDP 2152 -> 2152
    f.insert(f.end(), gtp.begin(), gtp.end());
    auto s = pcap::extractGtpu(f.data(), f.size());
    assert(s && s->len == gtp.size());
    auto h = gtpu::parse(s->data, s->len);
    assert(h && h->teid == 0xCAFE);
    f[23] = 6;                                     // TCP, not UDP
    assert(!pcap::extractGtpu(f.data(), f.size()));
}

int main() {
    testBasicHeader();
    testTruncatedAndBadVersion();
    testOptionalFieldsAndExtension();
    testFilterAndSampling();
    testExtractFromEthernetFrame();
    std::puts("all tests passed");
}
