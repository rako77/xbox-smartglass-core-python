import logging
# import gevent
import asyncio

from xbox.sg.crypto import PKCS7Padding
from xbox.sg.utils.events import Event
from xbox.auxiliary import packer
from xbox.auxiliary.packet import aux_header_struct, AUX_PACKET_MAGIC
from xbox.auxiliary.crypto import AuxiliaryStreamCrypto

log = logging.getLogger(__name__)


class AuxiliaryPackerException(Exception):
    pass


class ConsoleConnection(object):
    BUFFER_SIZE = 2048

    def __init__(self, address, port, crypto):
        self.host = (address, port)
        self.crypto = crypto

        self._socket = None
        self._recv_thread = None

        self.on_message = Event()

    def start(self):
        self._socket = gevent.socket.create_connection(self.host)
        self._recv_thread = gevent.spawn(self._recv)

    def stop(self):
        self._socket.close()
        gevent.kill(self._recv_thread)

    def handle(self, data):
        try:
            msg = packer.unpack(data, self.crypto)
            # Fire event
            self.on_message(msg)
        except Exception as e:
            log.exception("Exception while handling Console Aux data, error: {}".format(e))

    def _recv(self):
        while True:
            gevent.socket.wait_read(self._socket.fileno())
            data = self._socket.recv(4)
            header = aux_header_struct.parse(data)

            if header.magic != AUX_PACKET_MAGIC:
                raise Exception('Invalid packet magic received from console')

            payload_sz = header.payload_size + PKCS7Padding.size(header.payload_size, 16)
            remaining_payload_bytes = payload_sz

            while remaining_payload_bytes > 0:
                gevent.socket.wait_read(self._socket.fileno())
                tmp = self._socket.recv(remaining_payload_bytes)
                remaining_payload_bytes -= len(tmp)
                data += tmp

            data += self._socket.recv(32)

            self.handle(data)

    def send(self, msg):
        packets = packer.pack(msg, self.crypto)

        if not packets:
            raise Exception('No data')

        for packet in packets:
            self._socket.send(packet)


class LocalConnection(asyncio.Protocol):
    data_received_event = Event()
    connection_made_event = Event()

    def connection_made(self, transport):
        self.transport = transport
        self.connection_made(transport)

    def data_received(self, data):
        self.data_received(data)

    def close_connection(self):
        print('Close the client socket')
        self.transport.close()


class AuxiliaryRelayService(object):
    def __init__(self, loop, connection_info, listen_port):
        if len(connection_info.endpoints) > 1:
            raise Exception('Auxiliary Stream advertises more than one endpoint!')

        self._loop = loop
        self.crypto = AuxiliaryStreamCrypto.from_connection_info(connection_info)
        self.target_ip = connection_info.endpoints[0].ip
        self.target_port = connection_info.endpoints[0].port

        self.console_connection = ConsoleConnection(self.target_ip, self.target_port, self.crypto)
        self.server = self._loop.create_server(
            lambda: LocalConnection(),
            '0.0.0.0', listen_port)

        self.client_transport = None

    async def run(self):
        async with self.server as local_connection:
            local_connection.data_received_event += self._handle_client_data
            local_connection.connection_made_event += self.connection_made
            self.server.serve_forever()

    def connection_made(self, transport):
        self.client_transport = transport
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))

        self.console_connection.on_message += self._handle_console_data
        self.console_connection.start()

    def _handle_console_data(self, data):
        # Data from console gets decrypted and forwarded to aux client
        if self.client_transport:
            self.client_transport.send(data)

    def _handle_client_data(self, data):
        # Data from aux client gets encrypted and sent to console
        self.console_connection.send(data)
