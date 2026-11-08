#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pcap {

using Packet = std::vector<uint8_t>;

// Reads a classic .pcap file (Ethernet link type). Returns false on bad file.
bool readFile(const std::string& path, std::vector<Packet>& out);

struct Span { const uint8_t* data; size_t len; };

// Ethernet (+ optional VLAN) -> IPv4 -> UDP port 2152 -> returns the GTP-U bytes.
std::optional<Span> extractGtpu(const uint8_t* frame, size_t len);

}  // namespace pcap
