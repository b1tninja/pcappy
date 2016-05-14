from . import Frame, MacAddress, Layer3


class Ethernet2(Frame):
    parsers = dict([(getattr(parser, 'ether_type'), parser) for parser in Layer3.__subclasses__()])

    def __init__(self, dst, src, ether_type, data=b''):
        self.dst = MacAddress(dst)
        self.src = MacAddress(src)
        self.ether_type = ether_type
        self.data = data
        self.datagram = False

    @classmethod
    def parse(cls, payload):
        # TODO: add some sanity checking for lengths / padding
        dst, src = (payload[0:6], payload[6:12])
        # ether_type = struct.unpack_from('!H', payload, 12)
        ether_type = payload[12] << 8 | payload[13]
        if ether_type == ieee8021q.tpid:
            tag = ieee8021q_header.parse(payload[14:16])
            ether_type = payload[16:18]
            data = payload[18:]
            return ieee8021q(dst, src, tag, ether_type, data)
        elif ether_type == ieee8021ad.tpid:
            stag = ieee8021q_header.parse(payload[14:16])
            ctag = ieee8021q_header.parse(payload[16:18])
            ether_type = payload[18:20]
            data = payload[20:]
            return ieee8021ad(dst, src, stag, ctag, ether_type, data)
        else:
            data = payload[14:]
            return cls(dst, src, ether_type, data)

    def get_datagram(self):
        if self.datagram is False:
            if self.ether_type in self.parsers:
                try:
                    self.datagram = self.parsers[self.ether_type].parse(self.data)
                except:
                    pass
            else:
                self.datagram = None

        return self.datagram

    def __repr__(self):
        return "<Frame src=%s dst=%s len=%d>" % (self.src, self.dst, len(self.data))


class ieee8021q(Ethernet2):
    tpid = 0x8100

    def __init__(self, dst, src, tag, ether_type, data):
        super(ieee8021q, self).__init__(dst, src, ether_type, data)
        self.tag = tag


class ieee8021ad(Ethernet2):
    tpid = 0x88a8

    def __init__(self, dst, src, stag, ctag, ether_type, data):
        super(ieee8021ad, self).__init__(dst, src, ether_type, data)
        self.stag = stag
        self.ctag = ctag


class ieee8021q_header(object):
    def __init__(self, pcp, dei, vlan):
        self.pcp = pcp
        self.dei = dei
        self.vlan = vlan

    @classmethod
    def parse(cls, buffer):
        assert len(buffer) == 2
        pcp = buffer[0] >> 5
        dei = bool(buffer[0] & 0b00010000)
        vlan = ((buffer[0] & 0b00001111) << 4) | buffer[1]
        return cls(pcp, dei, vlan)
