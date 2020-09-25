"""
Console

Console class is a wrapper around the protocol, can be used to
`discover`, `poweron` and `connect`.
Also stores various device status informations.

It can be either created manually or instantiated via `DiscoveryResponse`
message. However, calling static method `discover` does all that for you
automatically.

Example:
    Discovery and connecting::

        import sys
        from xbox.sg.console import Console
        from xbox.sg.enum import ConnectionState

        discovered = Console.discover(timeout=1)
        if len(discovered):
            console = discovered[0]
            console.connect()
            if console.connection_state != ConnectionState.Connected:
                print("Connection failed")
                sys.exit(1)
            console.wait(1)

            try:
                console.protocol.serve_forever()
            except KeyboardInterrupt:
                pass
        else:
            print("No consoles discovered")
            sys.exit(1)
"""

import asyncio
import socket
from uuid import UUID
from typing import Optional, List, Union

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from xbox.sg.crypto import Crypto
from xbox.sg.manager import MediaManager, InputManager, TextManager
from xbox.sg.enum import PairedIdentityState, DeviceStatus, ConnectionState, \
    MessageType, PrimaryDeviceFlag, ActiveTitleLocation, AckStatus, \
    ServiceChannel, MediaControlCommand, GamePadButton
from xbox.sg.protocol import SmartglassProtocol, ProtocolError
from xbox.sg.utils.events import Event
from xbox.sg.utils.struct import XStruct
from xbox.stump.manager import StumpManager


class Console(object):
    __protocol__: SmartglassProtocol = None

    def __init__(
        self,
        address: str,
        name: str,
        uuid: UUID,
        liveid: str,
        flags: PrimaryDeviceFlag = PrimaryDeviceFlag.Null,
        last_error: int = 0,
        public_key: EllipticCurvePublicKey = None
    ):
        """
        Initialize an instance of Console

        Args:
            address: IP address of console.
            flags: Primary device flags
            name: Name of console.
            uuid: UUID of console.
            liveid: Live ID of console.
            public_key: Console's Public Key.
        """
        self.address = address
        self.name = name
        self.uuid = uuid
        self.liveid = liveid
        self.flags = flags
        self.last_error = last_error
        self._public_key = None
        self._crypto = None

        if public_key:
            # This sets up the crypto context
            self.public_key = public_key

        self.media: Optional[MediaManager] = None
        self.input: Optional[InputManager] = None
        self.text: Optional[TextManager] = None
        self.stump: Optional[StumpManager] = None
        # Note: NanoManager and TitleManager have to be handled externally

        self._device_status = DeviceStatus.Unavailable
        self._connection_state = ConnectionState.Disconnected
        self._pairing_state = PairedIdentityState.NotPaired
        self._console_status = None
        self._active_surface = None

        self.on_device_status = Event()
        self.on_connection_state = Event()
        self.on_pairing_state = Event()
        self.on_console_status = Event()
        self.on_active_surface = Event()
        self.on_timeout = Event()

        self.power_on = self._power_on  # Dirty hack

        self.protocol: Optional[SmartglassProtocol] = None

    def __repr__(self) -> str:
        return f'<Console addr={self.address} name={self.name} ' \
               f'uuid={self.uuid}liveid={self.liveid} flags={self.flags} ' \
               f'last_error={self.last_error}>'

    async def __aenter__(self):
        return self

    async def __aexit__(self) -> None:
        await self.disconnect()

    @staticmethod
    async def wait(seconds: int) -> None:
        """
        Wrapper around `asyncio.sleep`

        Args:
            seconds: Seconds to wait.

        Returns: None
        """
        await asyncio.sleep(seconds)

    async def _ensure_protocol_started(self) -> None:
        """
        Regular protocol instance, setup with crypto and destination address.
        Targeted at communication with a specific console.

        Returns:
            None
        """
        if not self.protocol:
            loop = asyncio.get_running_loop()
            _, self.protocol = await loop.create_datagram_endpoint(
                SmartglassProtocol,
                family=socket.AF_INET,
                remote_addr=(self.address, 5050),
                allow_broadcast=True
            )
            self.protocol.crypto = self._crypto

    @classmethod
    async def _ensure_global_protocol_started(cls) -> None:
        """
        Global protocol instance, used for network wide discovery and poweron.
        """
        if not cls.__protocol__:
            loop = asyncio.get_running_loop()
            _, cls.__protocol__ = await loop.create_datagram_endpoint(
                SmartglassProtocol,
                family=socket.AF_INET,
                allow_broadcast=True
            )

    @classmethod
    def from_message(cls, address: str, msg: XStruct):
        """
        Initialize the class with a `DiscoveryResponse`.

        Args:
            address: IP address of the console
            msg: Discovery Response struct

        Returns: Console instance

        """
        payload = msg.unprotected_payload
        console = cls(
            address, payload.name, payload.uuid, payload.cert.liveid,
            payload.flags, payload.last_error, payload.cert.pubkey
        )
        console.device_status = DeviceStatus.Available
        return console

    @classmethod
    def from_dict(cls, d: dict):
        return cls(d['address'], d['name'], UUID(d['uuid']), d['liveid'])

    def to_dict(self) -> dict:
        return dict(
            address=self.address,
            name=self.name,
            uuid=str(self.uuid),
            liveid=self.liveid
        )

    @classmethod
    async def discover(cls, *args, **kwargs) -> List:
        """
        Discover consoles on the network.

        Args:
            *args:
            **kwargs:

        Returns:
            list: List of discovered consoles.

        """
        await cls._ensure_global_protocol_started()
        discovered = await cls.__protocol__.discover(*args, **kwargs)
        return [cls.from_message(a, m) for a, m in discovered.items()]

    @classmethod
    def discovered(cls) -> List:
        """
        Get list of already discovered consoles.

        Returns:
            list: List of discovered consoles.

        """
        discovered = cls.__protocol__.discovered
        return [cls.from_message(a, m) for a, m in discovered.items()]

    @classmethod
    async def power_on(
        cls,
        liveid: str,
        addr: Optional[str] = None,
        tries=2
    ) -> None:
        """
        Power On console with given Live ID.

        Optionally the IP address of the console can be supplied,
        this is useful if the console is stubborn and does not react
        to broadcast / multicast packets (due to routing issues).

        Args:
            liveid (str): Live ID of console.
            addr (str): IP address of console.
            tries (int): Poweron attempts, default: 2.

        Returns: None

        """
        await cls._ensure_global_protocol_started()
        await cls.__protocol__.power_on(liveid, addr, tries)

    async def _power_on(self, tries: int = 2) -> None:
        await Console.power_on(self.liveid, self.address, tries)

    async def connect(
        self,
        userhash: Optional[str] = None,
        xsts_token: Optional[str] = None
    ) -> ConnectionState:
        """
        Connect to the console

        If the connection fails, error will be stored in
        `self.connection_state`

        Raises:
            ConnectionException: If no authentication data is supplied and
                console disallows anonymous connection.

        Returns: Connection state
        """
        if self.connected:
            raise ConnectionError("Already connected")

        auth_data_available = bool(userhash and xsts_token)
        if not self.anonymous_connection_allowed and not auth_data_available:
            raise ConnectionError("Anonymous connection not allowed, please"
                                  " supply userhash and auth-token")

        await self._ensure_protocol_started()

        # Assign managers as protocol is running at this point
        self.media = MediaManager(self)
        self.input = InputManager(self)
        self.text = TextManager(self)
        self.stump = StumpManager(self)

        self.pairing_state = PairedIdentityState.NotPaired
        self.connection_state = ConnectionState.Connecting

        try:
            self.pairing_state = await self.protocol.connect(
                userhash=userhash,
                xsts_token=xsts_token
            )
        except ProtocolError as e:
            self.connection_state = ConnectionState.Error
            raise e

        self.connection_state = ConnectionState.Connected


        return self.connection_state

    async def launch_title(
        self,
        uri: str,
        location: ActiveTitleLocation = ActiveTitleLocation.Full
    ) -> AckStatus:
        """
        Launch a title by URI

        Args:
            uri: Launch uri
            location: Target title location

        Returns: Ack status
        """
        return await self.protocol.launch_title(uri, location)

    async def game_dvr_record(
        self,
        start_delta: int,
        end_delta: int
    ) -> AckStatus:
        """
        Start Game DVR recording

        Args:
            start_delta: Start time
            end_delta: End time

        Returns: Ack status
        """
        return await self.protocol.game_dvr_record(start_delta, end_delta)

    async def disconnect(self) -> None:
        """
        Disconnect from console.

        This will reset connection-, pairing-state,
        ActiveSurface and ConsoleStatus.

        Returns: None
        """
        if self.connection_state == ConnectionState.Connected:
            self.connection_state = ConnectionState.Disconnecting
            await self._reset_state()

    async def power_off(self) -> None:
        """
        Power off the console.

        No need to disconnect after.

        Returns: None
        """
        await self.protocol.power_off(self.liveid)
        await self._reset_state()
        self.device_status = DeviceStatus.Unavailable

    def _on_message(self, msg: XStruct, channel: ServiceChannel) -> None:
        """
        Internal handler for console specific messages aka.
        `PairedIdentityStateChange`, `ConsoleStatus` and
        `ActiveSurfaceChange`.

        Args:
            msg: Message data
            channel: Service channel

        Returns:
            None
        """
        msg_type = msg.header.flags.msg_type

        if msg_type == MessageType.PairedIdentityStateChanged:
            self.pairing_state = msg.protected_payload.state

        elif msg_type == MessageType.ConsoleStatus:
            self.console_status = msg.protected_payload

        elif msg_type == MessageType.ActiveSurfaceChange:
            self.active_surface = msg.protected_payload

    async def _on_timeout(self) -> None:
        """
        Internal handler for console connection timeout.

        Returns: None
        """
        await self._reset_state()
        self.device_status = DeviceStatus.Unavailable
        self.on_timeout()

    async def _reset_state(self) -> None:
        """
        Internal handler to reset the inital state of the console instance.

        Returns: None
        """
        if self.protocol and self.protocol.started:
            await self.protocol.stop()

        await self._ensure_protocol_started()

        self.connection_state = ConnectionState.Disconnected
        self.pairing_state = PairedIdentityState.NotPaired
        self.active_surface = None
        self.console_status = None

    @property
    def public_key(self) -> EllipticCurvePublicKey:
        """
        Console's public key.

        Returns: Foreign public key
        """
        return self._public_key

    @public_key.setter
    def public_key(self, key: Union[EllipticCurvePublicKey, bytes]) -> None:
        if isinstance(key, bytes):
            self._crypto = Crypto.from_bytes(key)
        else:
            self._crypto = Crypto(key)

        self._public_key = self._crypto.foreign_pubkey

    @property
    def device_status(self) -> DeviceStatus:
        """
        Current availability status

        Returns:
            :obj:`DeviceStatus`
        """
        return self._device_status

    @device_status.setter
    def device_status(self, status: DeviceStatus) -> None:
        self._device_status = status
        self.on_device_status(status)

    @property
    def connection_state(self) -> ConnectionState:
        """
        Current connection state

        Returns: Connection state
        """
        return self._connection_state

    @connection_state.setter
    def connection_state(self, state: ConnectionState) -> None:
        self._connection_state = state
        self.on_connection_state(state)

    @property
    def pairing_state(self) -> PairedIdentityState:
        """
        Current pairing state

        Returns:
            :obj:`PairedIdentityState`
        """
        return self._pairing_state

    @pairing_state.setter
    def pairing_state(self, state: PairedIdentityState) -> None:
        self._pairing_state = state
        self.on_pairing_state(state)

    @property
    def console_status(self):
        """
        Console status aka. kernel version, active titles etc.

        Returns:
            :obj:`XStruct`
        """
        return self._console_status

    @console_status.setter
    def console_status(self, status):
        self._console_status = status
        self.on_console_status(status)

    @property
    def active_surface(self):
        """
        Currently active surface

        Returns:
            :obj:`XStruct`
        """
        return self._active_surface

    @active_surface.setter
    def active_surface(self, active_surface) -> None:
        self._active_surface = active_surface
        self.on_active_surface(active_surface)

    @property
    def available(self) -> bool:
        """
        Check whether console is available aka. discoverable

        Returns: `True` if console is available, `False` otherwise
        """
        return self.device_status == DeviceStatus.Available

    @property
    def paired(self) -> bool:
        """
        Check whether client is paired to console

        Returns: `True` if console is paired, `False` otherwise
        """
        return self.pairing_state == PairedIdentityState.Paired

    @property
    def connected(self) -> bool:
        """
        Check whether client is successfully connected to console

        Returns: `True` if connected, `False` otherwise
        """
        return self.connection_state == ConnectionState.Connected

    @property
    def authenticated_users_allowed(self) -> bool:
        """
        Check whether authenticated users are allowed to connect

        Returns: `True` if authenticated users are allowed, `False` otherwise
        """
        return bool(self.flags & PrimaryDeviceFlag.AllowAuthenticatedUsers)

    @property
    def console_users_allowed(self) -> bool:
        """
        Check whether console users are allowed to connect

        Returns: `True` if console users are allowed, `False` otherwise
        """
        return bool(self.flags & PrimaryDeviceFlag.AllowConsoleUsers)

    @property
    def anonymous_connection_allowed(self) -> bool:
        """
        Check whether anonymous connection is allowed

        Returns: `True` if anonymous connection is allowed, `False` otherwise
        """
        return bool(self.flags & PrimaryDeviceFlag.AllowAnonymousUsers)

    @property
    def is_certificate_pending(self) -> bool:
        """
        Check whether certificate is pending

        Returns: `True` if certificate is pending, `False` otherwise
        """
        return bool(self.flags & PrimaryDeviceFlag.CertificatePending)
