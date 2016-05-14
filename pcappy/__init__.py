from binascii import hexlify


class Frame(object):
    pass


class Packet(object):
    pass


class HWAddr(bytes):
    hwtype = None

    def __repr__(self):
        return hexlify(self)

    @classmethod
    def from_type_bytes(cls, hwtype, addr):
        if hwtype == 0x0001:
            return MacAddress(addr)
        else:
            hwaddr = HWAddr(addr)
            hwaddr.hwtype = hwtype
            return hwaddr


class MacAddress(HWAddr):
    def __str__(self):
        return ':'.join(map(lambda b: '%02X' % b, self))


class Layer3(object):
    pass
