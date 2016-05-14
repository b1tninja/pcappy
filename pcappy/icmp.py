import binascii
from enum import IntEnum

from . import Packet


class ICMP_MessageType(IntEnum):
    echo_reply = 0
    destination_unreachable = 3
    source_quench = 4
    redirect = 5
    echo = 8
    time_exceeded = 11
    parameter_problem = 12
    timestamp = 13
    timestamp_reply = 14
    information_request = 15
    information_reply = 16


class ICMP(Packet):
    protocol = 1

    def __init__(self, icmp_type, code, checksum, reserved, data):
        self.icmp_type = icmp_type
        self.code = code
        self.checksum = checksum
        self.reserved = reserved
        self.data = data

    @classmethod
    def parse(cls, payload):
        # parsers = dict([(getattr(parser, 'icmp_type'), parser) for parser in cls.__subclasses__()])

        assert len(payload) >= 8
        icmp_type = ICMP_MessageType(payload[0])
        code = payload[1]
        checksum = payload[2:4]
        reserved = payload[4:8]
        data = payload[8:]

        # if icmp_type in parsers:
        #     cls = parsers[icmp_type]

        return cls(icmp_type, code, checksum, reserved, data)

    def __repr__(self):
        return "<%s, code=%d, checksum=%s, reserved=%s, data=%s>" % (
            self.icmp_type, self.code, binascii.hexlify(self.checksum), self.reserved, self.data)


class ICMPEchoReply(ICMP):
    icmp_type = 0


class ICMPUnreachable(ICMP):
    icmp_type = 0


class ICMPEcho(ICMP):
    icmp_type = 8
