#pragma once
#include <cstdint>
#include <optional>
#include "gtpu.hpp"

// Filters on TEID and keeps 1 out of every N matching packets (deterministic sampling).
class Filter {
public:
    Filter(std::optional<uint32_t> teid, uint32_t sampleEveryN)
        : teid_(teid), n_(sampleEveryN == 0 ? 1 : sampleEveryN) {}

    bool accept(const gtpu::Header& h) {
        if (teid_ && h.teid != *teid_) return false;
        return (seen_++ % n_) == 0;
    }

private:
    std::optional<uint32_t> teid_;
    uint32_t n_;
    uint64_t seen_ = 0;
};
