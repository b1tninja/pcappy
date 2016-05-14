import struct

from . import Packet


class UDP(Packet):
    protocol = 17

    def __init__(self, src, dst, data, length=None, checksum=None):
        if length is None:
            length = len(data)

        if checksum is None:
            self.checksum = checksum

        self.src = src
        self.dst = dst
        self.length = length
        self.checksum = checksum
        self.data = data

    @classmethod
    def parse(cls, payload):
        try:
            assert len(payload) >= 8
            src, dst, length, checksum = struct.unpack_from('!HHHH', payload)
            data = payload[8:]
            return cls(src, dst, data, length, checksum)

        except AssertionError:
            pass

    def __repr__(self):
        return "<UDP src=%d, dst=%d, length=%d, checksum=%s, payload=%s>" % (
            self.src, self.dst, self.length, self.checksum, self.data)
