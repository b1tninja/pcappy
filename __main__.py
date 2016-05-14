import asyncio
import socket

from pcappy.raw import RawSocket

INTERFACE = 'wlp3s0'

# TODO: usage of payload vs data
# TODO: switch over to the get_datagram get_packet type mechanism to prevent over-zealous processing
# TODO: Enums for proto, etc


if __name__ == '__main__':
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, )
    sock.bind((INTERFACE, socket.SOCK_RAW))

    loop = asyncio.get_event_loop()
    loop.run_until_complete(loop.create_connection(RawSocket, sock=sock))

    loop.run_forever()
