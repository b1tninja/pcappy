import asyncio
import socket
import binascii
import struct
from enum import IntEnum
import ipaddress

INTERFACE = 'eno1'

# TODO: usage of payload vs data
# TODO: switch over to the get_datagram get_packet type mechanism to prevent over-zealous processing
# TODO: Enums for proto, etc

class Packet(object):
    pass

class Layer3(object):
    pass

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
        return "<%s, code=%d, checksum=%s, reserved=%s, data=%s>" % (self.icmp_type, self.code, binascii.hexlify(self.checksum), self.reserved, self.data)

class ICMPEchoReply(ICMP):
    icmp_type = 0

class ICMPUnreachable(ICMP):
    icmp_type = 0

class ICMPEcho(ICMP):
    icmp_type = 8


class TCP(Packet):
    protocol = 6

    FLAG_NS = 1<<8
    FLAG_CWR = 1<<7
    FLAG_ECE = 1<<6
    FLAG_URG = 1<<5
    FLAG_ACK = 1<<4
    FLAG_PSH = 1<<3
    FLAG_RST = 1<<2
    FLAG_SYN = 1<<1
    FLAG_FIN = 1

    def __init__(self, src, dst, seq, ack, data, data_offset=20, reserved=0, flags=0, window_size=0, checksum=None, urg_ptr=0, options=b''):
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
        assert(len(payload) >= 20)
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
        for n, flag in enumerate(reversed(['NS','CWR','ECE','URG','ACK','PSH','RST','SYN','FIN'])):
            if self.flags & 1<<n:
                flags.append(flag)

        return "<TCP src=%d, dst=%d, flags=%s, offset=%d, size=%d %s>" % (self.src, self.dst, ','.join(flags), self.data_offset, len(self.data), self.data)


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
            return cls(src,dst,data,length,checksum)

        except AssertionError:
            pass




    def __repr__(self):
        return "<UDP src=%d, dst=%d, length=%d, checksum=%s, payload=%s>" % (self.src, self.dst, self.length, self.checksum, self.data)


class IP(Layer3):
    ether_type = 0x0800
    parsers = dict([(getattr(parser, 'protocol'), parser) for parser in Packet.__subclasses__()])

    def __init__(self, version, ihl, dscp, ecn, length, identification, flags, fragment_offset, ttl, protocol, checksum, src, dst, options, payload):
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
            data = payload[20+ihl:]
        else:
            options = None
            data = payload[20:]

        return cls(version, ihl, dscp, ecn, length, identification, flags, fragment_offset, ttl, protocol, checksum, src, dst, options, data)

    def __repr__(self):
        return ("<IP src=%s dst=%s proto=%d size=%d %s>" % (ipaddress.IPv4Address(self.src), ipaddress.IPv4Address(self.dst), self.protocol, len(self.payload), self.packet if self.packet else binascii.hexlify(self.payload)))


class ARP_OPCODE(IntEnum):
    REQUEST = 1
    REPLY = 2
    RARP_REQUEST = 3
    RARP_REPLY = 4


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
        hwtype = payload[0:2]
        lltype = payload[2:4]
        hwsize = payload[4]
        llsize = payload[5]
        opcode = ARP_OPCODE(payload[6]<<8 | payload[7])
        src_hwaddr = payload[8:8+hwsize]
        src_lladdr = payload[8+hwsize:8+hwsize+llsize]
        dst_hwaddr = payload[8+hwsize+llsize:8+hwsize*2+llsize]
        dst_lladdr = payload[8+hwsize*2+llsize:8+hwsize*2+llsize*2]
        return cls(hwtype, lltype, hwsize, llsize, opcode, src_hwaddr, src_lladdr, dst_hwaddr, dst_lladdr)

    def encode(self):
        return self.hwtype + self.lltype + struct.pack('!BBH', self.hwsize ,self.llsize, int(self.opcode)) + self.src_hwaddr + self.src_lladdr + self.dst_hwaddr + self.dst_lladdr

    def __repr__(self):
        return"<%s src_hwaddr=%s src_lladdr=%s dst_hwaddr=%s dst_lladdr=%s>" % (self.opcode,
                                                                                binascii.hexlify(self.src_hwaddr),
                                                                                binascii.hexlify(self.src_lladdr),
                                                                                binascii.hexlify(self.dst_hwaddr),
                                                                                binascii.hexlify(self.dst_lladdr))


class Frame(object):
    pass


class Ethernet(Frame):
    parsers = dict([(struct.pack('!H', getattr(parser,'ether_type')), parser) for parser in Layer3.__subclasses__()])

    def __init__(self, dst, src, ether_type, data=b''):
        self.dst = dst
        self.src = src
        self.ether_type = ether_type
        self.data = data
        self.datagram = False

    @classmethod
    def parse(cls, payload):
        dst, src = (payload[0:6], payload[6:12])
        ether_type = struct.unpack_from('!H', payload, 12)
        if ether_type == 0x8100:
            # assert len(payload) >= 38 TODO: consult 8023ac
            pcp = payload[14] >> 5
            dei = bool(payload[14] & 0b00010000)
            vlan = ((payload[14] & 0b00001111) << 4) | payload[15]
            ether_type = payload[16:18]
            data = payload[18:]

        elif ether_type == 0x88a8:
            # assert len(payload) >= 34
            stag, ctag, ether_type, data = (payload[14:16], payload[16:20], payload[20:22], payload[22:])
        else:
            ether_type, data = (payload[12:14], payload[14:])
            # assert len(payload) >= 46

        # TODO: decide what to do with vlan info... currently just throwing it away
        return cls(dst, src, ether_type, data)

    def get_datagram(self):
        if self.datagram is False:
            if self.ether_type in self.parsers:
                self.datagram = self.parsers[self.ether_type].parse(self.data)
            else:
                self.datagram = None

        return self.datagram

    def __repr__(self):
        return "<Frame src=%s dst=%s len=%d>" % (binascii.hexlify(self.dst), binascii.hexlify(self.src), len(self.data))

class ieee8021q(Frame):
    #TODO: consider subclassing ethernet for the vlan stuff?
    pass


class ieee8021ad(Frame):
    pass


class RawSocket(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        assert len(data) >= 14
        frame = Ethernet.parse(data)
        datagram = frame.get_datagram()
        print(frame, datagram)

        # TODO: Abstract for generic layer3?
        if isinstance(datagram, IP):
            if isinstance(datagram.packet, ICMP):
                print(datagram.packet)


if __name__ == '__main__':
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,)
    sock.bind((INTERFACE, socket.SOCK_RAW))

    loop = asyncio.get_event_loop()
    loop.run_until_complete(loop.create_connection(RawSocket, sock=sock))

    loop.run_forever()