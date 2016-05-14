import struct
from enum import IntEnum

from . import Frame, HWAddr, Layer3
from .ip import LLAddr


class ARP(Layer3):
    ether_type = 0x0806

    def __init__(self, hwtype, lltype, hwsize, llsize, opcode, src_hwaddr, src_lladr, dst_hwaddr, dst_lladr):
        self.hwtype = hwtype
        self.lltype = lltype
        self.hwsize = hwsize
        self.llsize = llsize
        self.opcode = opcode
        self.src_hwaddr = src_hwaddr
        self.src_lladdr = src_lladr
        self.dst_hwaddr = dst_hwaddr
        self.dst_lladdr = dst_lladr

    @classmethod
    def parse(cls, payload):
        (hwtype, lltype, hwsize, llsize, opcode) = struct.unpack_from('!HHBBH', payload)
        # hwtype = payload[0:2]
        # lltype = payload[2:4]
        # hwsize = payload[4]
        # llsize = payload[5]
        opcode = ARP_OPCODE(opcode)
        src_hwaddr = payload[8:8 + hwsize]
        src_lladdr = payload[8 + hwsize:8 + hwsize + llsize]
        dst_hwaddr = payload[8 + hwsize + llsize:8 + hwsize * 2 + llsize]
        dst_lladdr = payload[8 + hwsize * 2 + llsize:8 + hwsize * 2 + llsize * 2]
        src_lladdr = LLAddr.from_type_bytes(lltype, src_lladdr)
        dst_lladdr = LLAddr.from_type_bytes(lltype, dst_lladdr)
        src_hwaddr = HWAddr.from_type_bytes(hwtype, src_hwaddr)
        dst_hwaddr = HWAddr.from_type_bytes(hwtype, dst_hwaddr)
        return cls(hwtype, lltype, hwsize, llsize, opcode, src_hwaddr, src_lladdr, dst_hwaddr, dst_lladdr)

    def encode(self):
        return struct.pack('!HHBBH',
                           self.hwtype,
                           self.lltype,
                           self.hwsize,
                           self.llsize,
                           int(self.opcode)) + bytes(self.src_hwaddr) + bytes(self.src_lladdr) + bytes(
            self.dst_hwaddr) + bytes(self.dst_lladdr)

    def __repr__(self):
        return "<%s src_hwaddr=%s src_lladdr=%s dst_hwaddr=%s dst_lladdr=%s>" % (self.opcode,
                                                                                 self.src_hwaddr,
                                                                                 self.src_lladdr,
                                                                                 self.dst_hwaddr,
                                                                                 self.dst_lladdr)


class ArpTable(object):
    def __init__(self):
        self.table = {}
        self.reverse_table = {}
        self.requests = {}
        self.replies = {}

    def parse(self, frame, datagram):
        assert isinstance(frame, Frame)
        assert isinstance(datagram, ARP)
        if datagram.opcode == ARP_OPCODE.REQUEST:
            pass


class ARP_OPCODE(IntEnum):
    REQUEST = 1
    REPLY = 2
    RARP_REQUEST = 3
    RARP_REPLY = 4
