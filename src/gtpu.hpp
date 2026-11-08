#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>

namespace gtpu {

// GTPv1-U header (3GPP TS 29.281). Mandatory part is 8 bytes; if any of the
// E/S/PN flags is set, 4 more bytes follow, then optional extension headers.
struct Header {
    uint8_t  version = 0;
    bool     protocolType = false;
    bool     hasExt = false, hasSeq = false, hasNpdu = false;
    uint8_t  messageType = 0;   // 255 = G-PDU (user data)
    uint16_t length = 0;        // bytes after the first 8
    uint32_t teid = 0;
    uint16_t seq = 0;
    uint8_t  npdu = 0;
    size_t   headerLen = 0;     // bytes before the user payload
};

// Returns nullopt for truncated or malformed packets (never reads out of bounds).
std::optional<Header> parse(const uint8_t* data, size_t len);

}  // namespace gtpu
