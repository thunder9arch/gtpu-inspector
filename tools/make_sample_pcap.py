"""Writes sample.pcap with GTP-U packets for TEIDs 0x1001..0x1003 (no Wireshark needed)."""
import struct

def frame(teid, payload=b"hello"):
    gtp = struct.pack("!BBHI", 0x30, 0xFF, len(payload), teid) + payload
    udp = struct.pack("!HHHH", 2152, 2152, 8 + len(gtp), 0) + gtp
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + udp
    return b"\x00" * 12 + b"\x08\x00" + ip

with open("sample.pcap", "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i in range(12):
        pkt = frame(0x1001 + i % 3)
        f.write(struct.pack("<IIII", i, 0, len(pkt), len(pkt)) + pkt)
print("wrote sample.pcap")
