#include "gtpu.hpp"

namespace gtpu {

static uint16_t be16(const uint8_t* p) { return uint16_t((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

std::optional<Header> parse(const uint8_t* data, size_t len) {
    if (!data || len < 8) return std::nullopt;

    Header h;
    const uint8_t flags = data[0];
    h.version      = flags >> 5;
    h.protocolType = (flags >> 4) & 1;
    h.hasExt       = (flags >> 2) & 1;
    h.hasSeq       = (flags >> 1) & 1;
    h.hasNpdu      = flags & 1;
    if (h.version != 1 || !h.protocolType) return std::nullopt;  // GTPv1 only

    h.messageType = data[1];
    h.length      = be16(data + 2);
    h.teid        = be32(data + 4);
    if (size_t(h.length) + 8 > len) return std::nullopt;          // truncated

    h.headerLen = 8;
    if (h.hasExt || h.hasSeq || h.hasNpdu) {
        if (len < 12) return std::nullopt;
        h.seq  = be16(data + 8);
        h.npdu = data[10];
        uint8_t next = data[11];
        h.headerLen = 12;
        if (h.hasExt) {
            // Each extension: 1 byte length (in 4-byte units), content, 1 byte next-type.
            while (next != 0) {
                if (h.headerLen >= len) return std::nullopt;
                const size_t extBytes = size_t(data[h.headerLen]) * 4;
                if (extBytes == 0 || h.headerLen + extBytes > len) return std::nullopt;
                next = data[h.headerLen + extBytes - 1];
                h.headerLen += extBytes;
            }
        }
    }
    return h;
}

}  // namespace gtpu
