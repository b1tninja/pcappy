import binascii
import ipaddress

from . import Layer3
from . import Packet


class IP(Layer3):
    ether_type = 0x0800
    parsers = dict([(getattr(parser, 'protocol'), parser) for parser in Packet.__subclasses__()])

    def __init__(self, version, ihl, dscp, ecn, length, identification, flags, fragment_offset, ttl, protocol, checksum,
                 src, dst, options, payload):
        self.version = version
        self.ihl = ihl
        self.dscp = dscp
        self.ecn = ecn
        self.length = length
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.src = src
        self.dst = dst
        self.payload = payload

        if protocol in self.parsers:
            self.packet = self.parsers[protocol].parse(payload)
        else:
            self.packet = None

    @classmethod
    def parse(cls, payload):
        version = payload[0] >> 4
        ihl = (payload[0] & 0b1111) << 2
        dscp = payload[1] >> 2
        ecn = payload[1] & 0b11
        length = payload[2] << 8 | payload[3]
        identification = payload[4:6]
        flags = payload[6] >> 5
        fragment_offset = (payload[6] & 0b11111) << 8 | payload[7]
        ttl = payload[8]
        protocol = payload[9]
        checksum = payload[10:12]
        src = payload[12:16]
        dst = payload[16:20]

        if ihl > 20:
            options = payload[20:ihl]
            data = payload[20 + ihl:]
        else:
            options = None
            data = payload[20:]

        return cls(version, ihl, dscp, ecn, length, identification, flags, fragment_offset, ttl, protocol, checksum,
                   src, dst, options, data)

    def __repr__(self):
        return ("<IP src=%s dst=%s proto=%d size=%d %s>" % (
            ipaddress.IPv4Address(self.src), ipaddress.IPv4Address(self.dst), self.protocol, len(self.payload),
            self.packet if self.packet else binascii.hexlify(self.payload)))


class IPv4Address(ipaddress.IPv4Address):
    lltype = 0x0800

    def __bytes__(self):
        return self.packed


class IPv6Address(ipaddress.IPv6Address):
    def __bytes__(self):
        return self.packed


class LLAddr(bytes):
    lltype = None

    def __str__(self):
        return binascii.hexlify(self)

    @classmethod
    def from_type_bytes(cls, lltype, addr):
        if lltype == 0x0800:
            return IPv4Address(addr)
        else:
            lladdr = LLAddr(addr)
            lladdr.lltype = lltype
            return lladdr
