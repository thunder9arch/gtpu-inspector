# gtpu-inspector

C++17 tool that reads a `.pcap`, finds GTP-U (3GPP TS 29.281) packets on UDP port 2152,
parses the GTPv1-U header (TEID, message type, sequence number, extension headers),
and filters / samples traffic by TEID.

## Build and test
    g++ -std=c++17 -Wall -Wextra -o build/test_gtpu tests/test_gtpu.cpp src/gtpu.cpp src/pcap.cpp && ./build/test_gtpu
    g++ -std=c++17 -Wall -Wextra -o build/gtpu_tool src/main.cpp src/gtpu.cpp src/pcap.cpp
(or `cmake -B build && cmake --build build`)

## Run
    python3 tools/make_sample_pcap.py            # or capture your own in Wireshark
    ./build/gtpu_tool sample.pcap --teid 0x1002 --sample 2

## Design
- `gtpu.cpp`: bounds-checked header parser, returns `std::optional`, never reads past the buffer.
- `pcap.cpp`: classic pcap reader plus Ethernet/VLAN/IPv4/UDP decoding.
- `filter.hpp`: TEID match plus deterministic 1-in-N sampling.
- Tests cover valid, truncated, wrong-version, extension-header and non-UDP cases.

## Next steps
- Run on a real Wireshark capture and compare output with Wireshark's GTP dissector.
- Add GTP-C (UDP 2123) IMSI parsing, a Dockerfile, and GoogleTest.
"# gtpu-inspector" 
