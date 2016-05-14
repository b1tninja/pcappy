import struct

from . import Packet


class TCP(Packet):
    protocol = 6

    FLAG_NS = 1 << 8
    FLAG_CWR = 1 << 7
    FLAG_ECE = 1 << 6
    FLAG_URG = 1 << 5
    FLAG_ACK = 1 << 4
    FLAG_PSH = 1 << 3
    FLAG_RST = 1 << 2
    FLAG_SYN = 1 << 1
    FLAG_FIN = 1

    def __init__(self, src, dst, seq, ack, data, data_offset=20, reserved=0, flags=0, window_size=0, checksum=None,
                 urg_ptr=0, options=b''):
        self.src = src
        self.dst = dst
        self.seq = seq
        self.ack = ack
        assert (data_offset >= 20 and data_offset % 4 == 0)
        self.data_offset = data_offset
        self.reserved = reserved
        self.flags = flags
        # self.ns = bool(flags & self.FLAG_NS)
        # self.cwr = bool(flags & self.FLAG_CWR)
        # self.ece = bool(flags & self.FLAG_ECE)
        # self.urg = bool(flags & self.FLAG_URG)
        # self.ack = bool(flags & self.FLAG_ACK)
        # self.psh = bool(flags & self.FLAG_PSH)
        # self.rst = bool(flags & self.FLAG_RST)
        # self.syn = bool(flags & self.FLAG_SYN)
        # self.fin = bool(flags & self.FLAG_FIN)
        self.window_size = window_size
        self.checksum = checksum
        self.urg_ptr = urg_ptr
        self.options = options
        self.data = data

    @classmethod
    def parse(cls, payload):
        assert (len(payload) >= 20)
        (src, dst, seq, ack) = struct.unpack('!HHLL', payload[0:12])
        data_offset = (payload[12] >> 4) << 2
        assert data_offset >= 20
        reserved = (payload[12] >> 1) & 0b111
        # ns = bool(payload[12] & 1)
        # cwr = bool(payload[13] & 0b10000000)
        # ece = bool(payload[13] & 0b01000000)
        # urg = bool(payload[13] & 0b00100000)
        # ack = bool(payload[13] & 0b00010000)
        # psh = bool(payload[13] & 0b00001000)
        # rst = bool(payload[13] & 0b00000100)
        # syn = bool(payload[13] & 0b00000010)
        # fin = bool(payload[13] & 0b00000001)
        flags = ((payload[12] & 1) << 8) | payload[13]
        (window_size, checksum, urg_ptr) = struct.unpack('!HHH', payload[14:20])

        options = payload[20:data_offset]

        data = payload[data_offset:]

        return cls(src, dst, seq, ack, data, data_offset, reserved, flags, window_size, checksum, urg_ptr, options)

    def __repr__(self):
        flags = []
        for n, flag in enumerate(reversed(['NS', 'CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN'])):
            if self.flags & 1 << n:
                flags.append(flag)

        return "<TCP src=%d, dst=%d, flags=%s, offset=%d, size=%d %s>" % (
            self.src, self.dst, ','.join(flags), self.data_offset, len(self.data), self.data)
