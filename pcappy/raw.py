import asyncio

# These are loaded in "reverse hierchacal order" because __subclasses__() works only if the classes are imported first.
from .udp import UDP
from .tcp import TCP
from .icmp import ICMP
from .ip import IP
from .arp import ARP, ArpTable

from .ethernet import Ethernet2


class RawSocket(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self.arp_table = ArpTable()

    def data_received(self, data):
        assert len(data) >= 14
        frame = Ethernet2.parse(data)
        datagram = frame.get_datagram()

        if isinstance(datagram, ARP):
            self.arp_table.parse(frame, datagram)
            print(frame, datagram)

        if isinstance(datagram, IP):
            # print(frame, datagram, datagram.packet)
            if isinstance(datagram.packet, ICMP):
                print(frame, datagram, datagram.packet)
