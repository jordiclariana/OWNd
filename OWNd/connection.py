""" This module handles TCP connections to the OpenWebNet gateway """

import asyncio
import hmac
import hashlib
import string
import random
import logging
import socket
import time
from typing import Union, Optional, Callable, Awaitable
from urllib.parse import urlparse
from enum import Enum, auto

from .discovery import find_gateways, get_gateway, get_port
from .message import OWNMessage, OWNSignaling


class ConnectionState(Enum):
    """Connection state enumeration for tracking."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    NEGOTIATING = auto()
    CONNECTED = auto()
    RECONNECTING = auto()
    CLOSING = auto()
    FAILED = auto()


class OWNGateway:
    """Represents an OpenWebNet gateway device."""
    
    def __init__(self, discovery_info: dict):
        # Attributes potentially provided by user
        self.address = discovery_info.get("address")
        self._password = discovery_info.get("password")
        
        # Attributes retrieved from SSDP discovery
        self.ssdp_location = discovery_info.get("ssdp_location")
        self.ssdp_st = discovery_info.get("ssdp_st")
        
        # Attributes retrieved from UPnP device description
        self.device_type = discovery_info.get("deviceType")
        self.friendly_name = discovery_info.get("friendlyName")
        self.manufacturer = discovery_info.get("manufacturer", "BTicino S.p.A.")
        self.manufacturer_url = discovery_info.get("manufacturerURL")
        self.model_name = discovery_info.get("modelName", "Unknown model")
        self.model_number = discovery_info.get("modelNumber")
        self.serial_number = discovery_info.get("serialNumber")
        self.udn = discovery_info.get("UDN")
        
        # Attributes retrieved from SOAP service control
        self.port = discovery_info.get("port")

        self._log_id = f"[{self.model_name} gateway - {self.host}]"

    @property
    def unique_id(self) -> str:
        return self.serial_number

    @unique_id.setter
    def unique_id(self, unique_id: str) -> None:
        self.serial_number = unique_id

    @property
    def host(self) -> str:
        return self.address

    @host.setter
    def host(self, host: str) -> None:
        self.address = host

    @property
    def firmware(self) -> str:
        return self.model_number

    @firmware.setter
    def firmware(self, firmware: str) -> None:
        self.model_number = firmware

    @property
    def serial(self) -> str:
        return self.serial_number

    @serial.setter
    def serial(self, serial: str) -> None:
        self.serial_number = serial

    @property
    def password(self) -> str:
        return self._password

    @password.setter
    def password(self, password: str) -> None:
        self._password = password

    @property
    def log_id(self) -> str:
        return self._log_id

    @log_id.setter
    def log_id(self, id: str) -> None:
        self._log_id = id

    @classmethod
    async def get_first_available_gateway(cls, password: str = None):
        local_gateways = await find_gateways()
        local_gateways[0]["password"] = password
        return cls(local_gateways[0])

    @classmethod
    async def find_from_address(cls, address: str):
        if address is not None:
            return cls(await get_gateway(address))
        else:
            return await cls.get_first_available_gateway()

    @classmethod
    async def build_from_discovery_info(cls, discovery_info: dict):
        if (
            ("address" not in discovery_info or discovery_info["address"] is None)
            and "ssdp_location" in discovery_info
            and discovery_info["ssdp_location"] is not None
        ):
            discovery_info["address"] = urlparse(
                discovery_info["ssdp_location"]
            ).hostname

        if "port" in discovery_info and discovery_info["port"] is None:
            if (
                "ssdp_location" in discovery_info
                and discovery_info["ssdp_location"] is not None
            ):
                discovery_info["port"] = await get_port(discovery_info["ssdp_location"])
            elif "address" in discovery_info and discovery_info["address"] is not None:
                return await cls.find_from_address(discovery_info["address"])
            else:
                return await cls.get_first_available_gateway(
                    password=discovery_info.get("password")
                )

        return cls(discovery_info)


class OWNSession:
    """Connection to OpenWebNet gateway with improved reliability."""

    SEPARATOR = "##".encode()
    
    # Connection timeouts and retry settings
    CONNECT_TIMEOUT = 10  # seconds
    READ_TIMEOUT = 30  # seconds for normal operations
    NEGOTIATE_TIMEOUT = 15  # seconds for negotiation
    
    # Keepalive settings
    TCP_KEEPALIVE_IDLE = 30  # Start keepalive after 30s idle
    TCP_KEEPALIVE_INTERVAL = 10  # Send keepalive every 10s
    TCP_KEEPALIVE_COUNT = 3  # Fail after 3 missed keepalives
    
    # Reconnection settings
    MAX_RECONNECT_ATTEMPTS = 10
    RECONNECT_BASE_DELAY = 1  # seconds
    RECONNECT_MAX_DELAY = 60  # seconds
    
    def __init__(
        self,
        gateway: OWNGateway = None,
        connection_type: str = "test",
        logger: logging.Logger = None,
    ):
        """Initialize the session.
        
        Arguments:
            gateway: OpenWebNet gateway instance
            connection_type: used when logging to identify this session
            logger: instance of logging
        """
        self._gateway = gateway
        self._type = connection_type.lower()
        self._logger = logger or logging.getLogger(__name__)

        # Stream reader/writer
        self._stream_reader: Optional[asyncio.StreamReader] = None
        self._stream_writer: Optional[asyncio.StreamWriter] = None
        
        # Connection state tracking
        self._state = ConnectionState.DISCONNECTED
        self._state_lock = asyncio.Lock()
        self._last_activity = 0.0
        self._connect_time = 0.0
        self._reconnect_count = 0
        
        # Callbacks
        self._on_disconnect: Optional[Callable[[], Awaitable[None]]] = None
        self._on_reconnect: Optional[Callable[[], Awaitable[None]]] = None

    @property
    def gateway(self) -> OWNGateway:
        return self._gateway

    @gateway.setter
    def gateway(self, gateway: OWNGateway) -> None:
        self._gateway = gateway

    @property
    def logger(self) -> logging.Logger:
        return self._logger

    @logger.setter
    def logger(self, logger: logging.Logger) -> None:
        self._logger = logger

    @property
    def connection_type(self) -> str:
        return self._type

    @connection_type.setter
    def connection_type(self, connection_type: str) -> None:
        self._type = connection_type.lower()

    @property
    def state(self) -> ConnectionState:
        """Current connection state."""
        return self._state

    @property
    def is_connected(self) -> bool:
        """Check if session is connected and healthy."""
        return self._state == ConnectionState.CONNECTED

    @property
    def is_closing(self) -> bool:
        """Check if session is in the process of closing."""
        return self._state in (ConnectionState.CLOSING, ConnectionState.FAILED)

    @property
    def last_activity(self) -> float:
        """Timestamp of last activity (send or receive)."""
        return self._last_activity

    @property
    def uptime(self) -> float:
        """Seconds since connection was established."""
        if self._connect_time > 0:
            return time.time() - self._connect_time
        return 0.0

    def set_disconnect_callback(self, callback: Callable[[], Awaitable[None]]) -> None:
        """Set callback to be called when connection is lost."""
        self._on_disconnect = callback

    def set_reconnect_callback(self, callback: Callable[[], Awaitable[None]]) -> None:
        """Set callback to be called when reconnection succeeds."""
        self._on_reconnect = callback

    def _update_activity(self) -> None:
        """Update the last activity timestamp."""
        self._last_activity = time.time()

    async def _set_state(self, new_state: ConnectionState) -> None:
        """Thread-safe state transition."""
        async with self._state_lock:
            old_state = self._state
            self._state = new_state
            if old_state != new_state:
                self._logger.debug(
                    "%s State: %s -> %s",
                    self._gateway.log_id if self._gateway else "[unknown]",
                    old_state.name,
                    new_state.name
                )

    def _enable_tcp_keepalive(self) -> None:
        """Enable TCP keepalive on the underlying socket."""
        if self._stream_writer is None:
            return
            
        try:
            sock = self._stream_writer.get_extra_info('socket')
            if sock is None:
                return
                
            # Enable keepalive
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            # Linux-specific keepalive options
            if hasattr(socket, 'TCP_KEEPIDLE'):
                sock.setsockopt(
                    socket.IPPROTO_TCP, 
                    socket.TCP_KEEPIDLE, 
                    self.TCP_KEEPALIVE_IDLE
                )
            if hasattr(socket, 'TCP_KEEPINTVL'):
                sock.setsockopt(
                    socket.IPPROTO_TCP, 
                    socket.TCP_KEEPINTVL, 
                    self.TCP_KEEPALIVE_INTERVAL
                )
            if hasattr(socket, 'TCP_KEEPCNT'):
                sock.setsockopt(
                    socket.IPPROTO_TCP, 
                    socket.TCP_KEEPCNT, 
                    self.TCP_KEEPALIVE_COUNT
                )
                
            self._logger.debug(
                "%s TCP keepalive enabled (idle=%ds, interval=%ds, count=%d)",
                self._gateway.log_id,
                self.TCP_KEEPALIVE_IDLE,
                self.TCP_KEEPALIVE_INTERVAL,
                self.TCP_KEEPALIVE_COUNT
            )
        except (OSError, AttributeError) as e:
            self._logger.warning(
                "%s Could not enable TCP keepalive: %s",
                self._gateway.log_id,
                e
            )

    async def _handle_connection_lost(self, error: Optional[Exception] = None) -> None:
        """Handle connection loss gracefully."""
        if self._state in (ConnectionState.CLOSING, ConnectionState.FAILED):
            return
            
        await self._set_state(ConnectionState.DISCONNECTED)
        
        error_msg = f": {type(error).__name__}: {error}" if error else ""
        self._logger.warning(
            "%s Connection lost%s",
            self._gateway.log_id,
            error_msg
        )
        
        # Notify listener
        if self._on_disconnect:
            try:
                await self._on_disconnect()
            except Exception as e:
                self._logger.error(
                    "%s Error in disconnect callback: %s",
                    self._gateway.log_id,
                    e
                )

    @classmethod
    async def test_gateway(cls, gateway: OWNGateway) -> dict:
        connection = cls(gateway)
        return await connection.test_connection()

    async def test_connection(self) -> dict:
        """Test connection to gateway."""
        retry_count = 0
        retry_timer = 1

        while True:
            try:
                if retry_count > 2:
                    self._logger.error(
                        "%s Test session connection still refused after 3 attempts.",
                        self._gateway.log_id,
                    )
                    return None
                    
                await self._set_state(ConnectionState.CONNECTING)
                (
                    self._stream_reader,
                    self._stream_writer,
                ) = await asyncio.wait_for(
                    asyncio.open_connection(
                        self._gateway.address, self._gateway.port
                    ),
                    timeout=self.CONNECT_TIMEOUT
                )
                self._enable_tcp_keepalive()
                break
            except (ConnectionRefusedError, asyncio.TimeoutError) as e:
                self._logger.warning(
                    "%s Test session connection failed (%s), retrying in %ss.",
                    self._gateway.log_id,
                    type(e).__name__,
                    retry_timer,
                )
                await asyncio.sleep(retry_timer)
                retry_count += 1
                retry_timer *= 2

        try:
            await self._set_state(ConnectionState.NEGOTIATING)
            result = await self._negotiate()
            await self.close()
        except ConnectionResetError:
            error = True
            error_message = "password_retry"
            self._logger.error(
                "%s Negotiation reset while opening %s session. Wait 60 seconds before retrying.",
                self._gateway.log_id,
                self._type,
            )
            return {"Success": False, "Message": error_message}

        return result

    async def connect(self) -> Optional[dict]:
        """Connect to the gateway with retry logic."""
        self._logger.debug("%s Opening %s session.", self._gateway.log_id, self._type)

        retry_count = 0
        retry_timer = self.RECONNECT_BASE_DELAY

        while True:
            try:
                if retry_count > self.MAX_RECONNECT_ATTEMPTS:
                    self._logger.error(
                        "%s %s session connection failed after %d attempts.",
                        self._gateway.log_id,
                        self._type.capitalize(),
                        self.MAX_RECONNECT_ATTEMPTS,
                    )
                    await self._set_state(ConnectionState.FAILED)
                    return None
                
                await self._set_state(ConnectionState.CONNECTING)
                
                (
                    self._stream_reader,
                    self._stream_writer,
                ) = await asyncio.wait_for(
                    asyncio.open_connection(
                        self._gateway.address, self._gateway.port
                    ),
                    timeout=self.CONNECT_TIMEOUT
                )
                
                self._enable_tcp_keepalive()
                
                await self._set_state(ConnectionState.NEGOTIATING)
                result = await self._negotiate()
                
                if result and result.get("Success"):
                    await self._set_state(ConnectionState.CONNECTED)
                    self._connect_time = time.time()
                    self._update_activity()
                    self._reconnect_count = 0
                    
                    # Notify listener
                    if self._on_reconnect and retry_count > 0:
                        try:
                            await self._on_reconnect()
                        except Exception as e:
                            self._logger.error(
                                "%s Error in reconnect callback: %s",
                                self._gateway.log_id,
                                e
                            )
                    
                return result
                
            except (ConnectionRefusedError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError) as e:
                self._logger.warning(
                    "%s %s session connection failed (%s: %s), retrying in %ss.",
                    self._gateway.log_id,
                    self._type.capitalize(),
                    type(e).__name__,
                    str(e),
                    retry_timer,
                )
                await asyncio.sleep(retry_timer)
                retry_count += 1
                # Exponential backoff with max limit
                retry_timer = min(retry_timer * 2, self.RECONNECT_MAX_DELAY)
                
            except ConnectionResetError:
                self._logger.warning(
                    "%s %s session connection reset, retrying in 60s.",
                    self._gateway.log_id,
                    self._type.capitalize(),
                )
                await asyncio.sleep(60)
                retry_count += 1

    async def reconnect(self) -> Optional[dict]:
        """Force reconnection to the gateway."""
        self._reconnect_count += 1
        self._logger.info(
            "%s Reconnecting %s session (attempt %d)...",
            self._gateway.log_id,
            self._type,
            self._reconnect_count
        )
        
        await self._set_state(ConnectionState.RECONNECTING)
        await self.close(notify=False)
        return await self.connect()

    async def close(self, notify: bool = True) -> None:
        """Close the connection to the OpenWebNet gateway."""
        if self._state == ConnectionState.CLOSING:
            return
            
        await self._set_state(ConnectionState.CLOSING)

        if self._stream_writer is not None:
            try:
                self._stream_writer.close()
                await asyncio.wait_for(
                    self._stream_writer.wait_closed(),
                    timeout=5.0
                )
            except (asyncio.TimeoutError, Exception) as e:
                self._logger.debug(
                    "%s Error closing stream writer: %s",
                    self._gateway.log_id if self._gateway else "[unknown]",
                    e
                )
            finally:
                self._stream_writer = None
                self._stream_reader = None

        await self._set_state(ConnectionState.DISCONNECTED)
        
        if self._gateway is not None:
            self._logger.debug(
                "%s %s session closed.", 
                self._gateway.log_id, 
                self._type.capitalize()
            )

        if notify and self._on_disconnect:
            try:
                await self._on_disconnect()
            except Exception as e:
                self._logger.error(
                    "%s Error in disconnect callback: %s",
                    self._gateway.log_id,
                    e
                )

    async def _negotiate(self) -> dict:
        """Negotiate the session with the gateway."""
        type_id = 0 if self._type == "command" else 1
        error = False
        error_message = None

        self._logger.debug(
            "%s Negotiating %s session.", self._gateway.log_id, self._type
        )

        self._stream_writer.write(f"*99*{type_id}##".encode())
        await self._stream_writer.drain()

        raw_response = await asyncio.wait_for(
            self._stream_reader.readuntil(OWNSession.SEPARATOR),
            timeout=self.NEGOTIATE_TIMEOUT
        )
        resulting_message = OWNSignaling(raw_response.decode())

        if resulting_message.is_nack():
            self._logger.error(
                "%s Error while opening %s session.", self._gateway.log_id, self._type
            )
            error = True
            error_message = "connection_refused"

        raw_response = await asyncio.wait_for(
            self._stream_reader.readuntil(OWNSession.SEPARATOR),
            timeout=self.NEGOTIATE_TIMEOUT
        )
        resulting_message = OWNSignaling(raw_response.decode())
        
        if resulting_message.is_nack():
            error = True
            error_message = "negotiation_refused"
            self._logger.debug(
                "%s Reply: `%s`", self._gateway.log_id, resulting_message
            )
            self._logger.error(
                "%s Error while opening %s session.", self._gateway.log_id, self._type
            )
        elif resulting_message.is_sha():
            self._logger.debug(
                "%s Received SHA challenge: `%s`",
                self._gateway.log_id,
                resulting_message,
            )
            if self._gateway.password is None:
                error = True
                error_message = "password_required"
                self._logger.warning(
                    "%s Connection requires a password but none was provided.",
                    self._gateway.log_id,
                )
                self._stream_writer.write("*#*0##".encode())
                await self._stream_writer.drain()
            else:
                method = "sha"
                if resulting_message.is_sha_1():
                    method = "sha1"
                elif resulting_message.is_sha_256():
                    method = "sha256"
                self._logger.debug(
                    "%s Accepting %s challenge, initiating handshake.",
                    self._gateway.log_id,
                    method,
                )
                self._stream_writer.write("*#*1##".encode())
                await self._stream_writer.drain()
                
                raw_response = await asyncio.wait_for(
                    self._stream_reader.readuntil(OWNSession.SEPARATOR),
                    timeout=self.NEGOTIATE_TIMEOUT
                )
                resulting_message = OWNSignaling(raw_response.decode())
                
                if resulting_message.is_nonce():
                    server_random_string_ra = resulting_message.nonce
                    key = "".join(random.choices(string.digits, k=56))
                    client_random_string_rb = self._hex_string_to_int_string(
                        hmac.new(key=key.encode(), digestmod=method).hexdigest()
                    )
                    hashed_password = f"*#{client_random_string_rb}*{self._encode_hmac_password(method=method, password=self._gateway.password, nonce_a=server_random_string_ra, nonce_b=client_random_string_rb)}##"
                    self._logger.debug(
                        "%s Sending %s session password.",
                        self._gateway.log_id,
                        self._type,
                    )
                    self._stream_writer.write(hashed_password.encode())
                    await self._stream_writer.drain()
                    
                    try:
                        raw_response = await asyncio.wait_for(
                            self._stream_reader.readuntil(OWNSession.SEPARATOR),
                            timeout=self.NEGOTIATE_TIMEOUT,
                        )
                        resulting_message = OWNSignaling(raw_response.decode())
                        
                        if resulting_message.is_nack():
                            error = True
                            error_message = "password_error"
                            self._logger.error(
                                "%s Password error while opening %s session.",
                                self._gateway.log_id,
                                self._type,
                            )
                        elif resulting_message.is_nonce():
                            hmac_response = resulting_message.nonce
                            if hmac_response == self._decode_hmac_response(
                                method=method,
                                password=self._gateway.password,
                                nonce_a=server_random_string_ra,
                                nonce_b=client_random_string_rb,
                            ):
                                self._stream_writer.write("*#*1##".encode())
                                await self._stream_writer.drain()
                                self._logger.debug(
                                    "%s Session established successfully.", 
                                    self._gateway.log_id
                                )
                            else:
                                self._logger.error(
                                    "%s Server identity could not be confirmed.",
                                    self._gateway.log_id,
                                )
                                self._stream_writer.write("*#*0##".encode())
                                await self._stream_writer.drain()
                                error = True
                                error_message = "negotiation_error"
                                self._logger.error(
                                    "%s Error while opening %s session: HMAC authentication failed.",
                                    self._gateway.log_id,
                                    self._type,
                                )
                    except asyncio.IncompleteReadError:
                        error = True
                        error_message = "password_error"
                        self._logger.error(
                            "%s Password error while opening %s session.",
                            self._gateway.log_id,
                            self._type,
                        )
                    except asyncio.TimeoutError:
                        error = True
                        error_message = "password_timeout"
                        self._logger.error(
                            "%s Password timeout error while opening %s session.",
                            self._gateway.log_id,
                            self._type,
                        )
        elif resulting_message.is_nonce():
            self._logger.debug(
                "%s Received nonce: `%s`", self._gateway.log_id, resulting_message
            )
            if self._gateway.password is not None:
                hashed_password = f"*#{self._get_own_password(self._gateway.password, resulting_message.nonce)}##"
                self._logger.debug(
                    "%s Sending %s session password.", self._gateway.log_id, self._type
                )
                self._stream_writer.write(hashed_password.encode())
                await self._stream_writer.drain()
                
                raw_response = await asyncio.wait_for(
                    self._stream_reader.readuntil(OWNSession.SEPARATOR),
                    timeout=self.NEGOTIATE_TIMEOUT
                )
                resulting_message = OWNSignaling(raw_response.decode())
                
                if resulting_message.is_nack():
                    error = True
                    error_message = "password_error"
                    self._logger.error(
                        "%s Password error while opening %s session.",
                        self._gateway.log_id,
                        self._type,
                    )
                elif resulting_message.is_ack():
                    self._logger.debug(
                        "%s %s session established successfully.",
                        self._gateway.log_id,
                        self._type.capitalize(),
                    )
            else:
                error = True
                error_message = "password_required"
                self._logger.error(
                    "%s Connection requires a password but none was provided for %s session.",
                    self._gateway.log_id,
                    self._type,
                )
        elif resulting_message.is_ack():
            self._logger.debug(
                "%s %s session established successfully.",
                self._gateway.log_id,
                self._type.capitalize(),
            )
        else:
            error = True
            error_message = "negotiation_failed"
            self._logger.debug(
                "%s Unexpected message during negotiation: %s",
                self._gateway.log_id,
                resulting_message,
            )

        return {"Success": not error, "Message": error_message}

    def _get_own_password(self, password, nonce, test=False):
        """Calculate OWN password hash."""
        start = True
        num1 = 0
        num2 = 0
        password = int(password)
        if test:
            print("password: %08x" % (password))
        for character in nonce:
            if character != "0":
                if start:
                    num2 = password
                start = False
            if test:
                print("c: %s num1: %08x num2: %08x" % (character, num1, num2))
            if character == "1":
                num1 = (num2 & 0xFFFFFF80) >> 7
                num2 = num2 << 25
            elif character == "2":
                num1 = (num2 & 0xFFFFFFF0) >> 4
                num2 = num2 << 28
            elif character == "3":
                num1 = (num2 & 0xFFFFFFF8) >> 3
                num2 = num2 << 29
            elif character == "4":
                num1 = num2 << 1
                num2 = num2 >> 31
            elif character == "5":
                num1 = num2 << 5
                num2 = num2 >> 27
            elif character == "6":
                num1 = num2 << 12
                num2 = num2 >> 20
            elif character == "7":
                num1 = (
                    num2 & 0x0000FF00
                    | ((num2 & 0x000000FF) << 24)
                    | ((num2 & 0x00FF0000) >> 16)
                )
                num2 = (num2 & 0xFF000000) >> 8
            elif character == "8":
                num1 = (num2 & 0x0000FFFF) << 16 | (num2 >> 24)
                num2 = (num2 & 0x00FF0000) >> 8
            elif character == "9":
                num1 = ~num2
            else:
                num1 = num2

            num1 &= 0xFFFFFFFF
            num2 &= 0xFFFFFFFF
            if character not in "09":
                num1 |= num2
            if test:
                print("     num1: %08x num2: %08x" % (num1, num2))
            num2 = num1
        return num1

    def _encode_hmac_password(
        self, method: str, password: str, nonce_a: str, nonce_b: str
    ):
        """Encode password for HMAC authentication."""
        if method == "sha1":
            message = (
                self._int_string_to_hex_string(nonce_a)
                + self._int_string_to_hex_string(nonce_b)
                + "736F70653E"
                + "636F70653E"
                + hashlib.sha1(password.encode()).hexdigest()
            )
            return self._hex_string_to_int_string(
                hashlib.sha1(message.encode()).hexdigest()
            )
        elif method == "sha256":
            message = (
                self._int_string_to_hex_string(nonce_a)
                + self._int_string_to_hex_string(nonce_b)
                + "736F70653E"
                + "636F70653E"
                + hashlib.sha256(password.encode()).hexdigest()
            )
            return self._hex_string_to_int_string(
                hashlib.sha256(message.encode()).hexdigest()
            )
        else:
            return None

    def _decode_hmac_response(
        self, method: str, password: str, nonce_a: str, nonce_b: str
    ):
        """Decode HMAC response for verification."""
        if method == "sha1":
            message = (
                self._int_string_to_hex_string(nonce_a)
                + self._int_string_to_hex_string(nonce_b)
                + hashlib.sha1(password.encode()).hexdigest()
            )
            return self._hex_string_to_int_string(
                hashlib.sha1(message.encode()).hexdigest()
            )
        elif method == "sha256":
            message = (
                self._int_string_to_hex_string(nonce_a)
                + self._int_string_to_hex_string(nonce_b)
                + hashlib.sha256(password.encode()).hexdigest()
            )
            return self._hex_string_to_int_string(
                hashlib.sha256(message.encode()).hexdigest()
            )
        else:
            return None

    def _int_string_to_hex_string(self, int_string: str) -> str:
        hex_string = ""
        for i in range(0, len(int_string), 2):
            hex_string += f"{int(int_string[i:i+2]):x}"
        return hex_string

    def _hex_string_to_int_string(self, hex_string: str) -> str:
        int_string = ""
        for i in range(0, len(hex_string), 1):
            int_string += f"{int(hex_string[i:i+1], 16):0>2d}"
        return int_string


class OWNEventSession(OWNSession):
    """Event session with improved reliability and heartbeat support."""
    
    # Heartbeat settings
    HEARTBEAT_INTERVAL = 60  # seconds
    HEARTBEAT_TIMEOUT = 10  # seconds
    MAX_MISSED_HEARTBEATS = 3
    
    def __init__(self, gateway: OWNGateway = None, logger: logging.Logger = None):
        super().__init__(gateway=gateway, connection_type="event", logger=logger)
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._missed_heartbeats = 0

    @classmethod
    async def connect_to_gateway(cls, gateway: OWNGateway):
        connection = cls(gateway)
        await connection.connect()
        return connection

    async def connect(self) -> Optional[dict]:
        """Connect and start heartbeat monitoring."""
        result = await super().connect()
        if result and result.get("Success"):
            self._start_heartbeat()
        return result

    async def close(self, notify: bool = True) -> None:
        """Close and stop heartbeat monitoring."""
        self._stop_heartbeat()
        await super().close(notify)

    def _start_heartbeat(self) -> None:
        """Start the heartbeat monitoring task."""
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
        self._missed_heartbeats = 0
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    def _stop_heartbeat(self) -> None:
        """Stop the heartbeat monitoring task."""
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None

    async def _heartbeat_loop(self) -> None:
        """Periodic heartbeat to detect stale connections."""
        while self.is_connected:
            await asyncio.sleep(self.HEARTBEAT_INTERVAL)
            
            # Check if we've received any activity recently
            idle_time = time.time() - self._last_activity
            if idle_time < self.HEARTBEAT_INTERVAL:
                # We've had activity, reset missed heartbeats
                self._missed_heartbeats = 0
                continue
            
            # No activity for a while, check if connection is still alive
            self._missed_heartbeats += 1
            
            if self._missed_heartbeats >= self.MAX_MISSED_HEARTBEATS:
                self._logger.warning(
                    "%s No activity for %ds, missed %d heartbeats - connection may be dead",
                    self._gateway.log_id,
                    int(idle_time),
                    self._missed_heartbeats
                )
                await self._handle_connection_lost(
                    Exception(f"No activity for {int(idle_time)}s")
                )
                break

    async def get_next(self) -> Union[OWNMessage, str, None]:
        """Read the next message from the event bus with improved error handling."""
        try:
            data = await asyncio.wait_for(
                self._stream_reader.readuntil(OWNSession.SEPARATOR),
                timeout=self.READ_TIMEOUT * 2  # Event session can be idle longer
            )
            self._update_activity()
            self._missed_heartbeats = 0
            
            _decoded_data = data.decode()
            _message = OWNMessage.parse(_decoded_data)
            return _message if _message else _decoded_data
            
        except asyncio.TimeoutError:
            # Timeout is expected for event session - just means no events
            return None
            
        except asyncio.IncompleteReadError as e:
            self._logger.warning(
                "%s Connection interrupted (IncompleteReadError: %s), reconnecting...",
                self._gateway.log_id,
                e
            )
            await self._handle_connection_lost(e)
            await self.reconnect()
            return None
            
        except ConnectionError as e:
            self._logger.error(
                "%s Connection error (%s: %s), reconnecting...",
                self._gateway.log_id,
                type(e).__name__,
                e
            )
            await self._handle_connection_lost(e)
            await self.reconnect()
            return None
            
        except AttributeError as e:
            self._logger.exception(
                "%s Received data could not be parsed into a message: %s",
                self._gateway.log_id,
                e
            )
            return None
            
        except Exception as e:
            self._logger.exception(
                "%s Event session error (%s: %s)",
                self._gateway.log_id,
                type(e).__name__,
                e
            )
            return None


class OWNCommandSession(OWNSession):
    """Command session with improved send reliability."""
    
    MAX_SEND_RETRIES = 3
    SEND_RETRY_DELAY = 0.5  # seconds
    
    def __init__(self, gateway: OWNGateway = None, logger: logging.Logger = None):
        super().__init__(gateway=gateway, connection_type="command", logger=logger)

    @classmethod
    async def send_to_gateway(cls, message: str, gateway: OWNGateway):
        connection = cls(gateway)
        await connection.connect()
        await connection.send(message)

    @classmethod
    async def connect_to_gateway(cls, gateway: OWNGateway):
        connection = cls(gateway)
        await connection.connect()
        return connection

    async def send(
        self, 
        message, 
        is_status_request: bool = False, 
        attempt: int = 1
    ) -> bool:
        """Send a command with improved error handling and retry logic."""
        if not self.is_connected:
            self._logger.warning(
                "%s Not connected, attempting to reconnect before sending...",
                self._gateway.log_id
            )
            result = await self.reconnect()
            if not result or not result.get("Success"):
                self._logger.error(
                    "%s Could not reconnect to send message `%s`.",
                    self._gateway.log_id,
                    message
                )
                return False

        try:
            self._stream_writer.write(str(message).encode())
            await self._stream_writer.drain()
            self._update_activity()
            
            raw_response = await asyncio.wait_for(
                self._stream_reader.readuntil(OWNSession.SEPARATOR),
                timeout=self.READ_TIMEOUT
            )
            self._update_activity()
            resulting_message = OWNMessage.parse(raw_response.decode())

            while not isinstance(resulting_message, OWNSignaling):
                self._logger.debug(
                    "%s Message `%s` received response `%s`.",
                    self._gateway.log_id,
                    message,
                    resulting_message,
                )
                raw_response = await asyncio.wait_for(
                    self._stream_reader.readuntil(OWNSession.SEPARATOR),
                    timeout=self.READ_TIMEOUT
                )
                self._update_activity()
                resulting_message = OWNMessage.parse(raw_response.decode())

            if resulting_message.is_nack():
                if attempt <= self.MAX_SEND_RETRIES:
                    self._logger.warning(
                        "%s Message `%s` got NACK. Retrying (%d/%d) in %.1fs...",
                        self._gateway.log_id,
                        message,
                        attempt,
                        self.MAX_SEND_RETRIES,
                        self.SEND_RETRY_DELAY
                    )
                    await asyncio.sleep(self.SEND_RETRY_DELAY)
                    return await self.send(message, is_status_request, attempt + 1)
                else:
                    self._logger.error(
                        "%s Could not send message `%s` after %d attempts (NACK).",
                        self._gateway.log_id,
                        message,
                        self.MAX_SEND_RETRIES
                    )
                    return False
                    
            elif resulting_message.is_ack():
                log_message = "%s Message `%s` was successfully sent."
                if not is_status_request:
                    self._logger.info(log_message, self._gateway.log_id, message)
                else:
                    self._logger.debug(log_message, self._gateway.log_id, message)
                return True
            else:
                self._logger.warning(
                    "%s Unexpected response to message `%s`: %s",
                    self._gateway.log_id,
                    message,
                    resulting_message
                )
                return False

        except asyncio.TimeoutError:
            self._logger.error(
                "%s Timeout sending message `%s`. Reconnecting...",
                self._gateway.log_id,
                message
            )
            await self._handle_connection_lost(asyncio.TimeoutError("Send timeout"))
            
            if attempt <= self.MAX_SEND_RETRIES:
                await self.reconnect()
                return await self.send(
                    message=message, 
                    is_status_request=is_status_request,
                    attempt=attempt + 1
                )
            return False

        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError, OSError) as e:
            self._logger.warning(
                "%s Connection error sending message `%s` (%s: %s). Reconnecting...",
                self._gateway.log_id,
                message,
                type(e).__name__,
                e
            )
            await self._handle_connection_lost(e)
            
            if attempt <= self.MAX_SEND_RETRIES:
                await asyncio.sleep(self.SEND_RETRY_DELAY * attempt)
                await self.reconnect()
                return await self.send(
                    message=message, 
                    is_status_request=is_status_request,
                    attempt=attempt + 1
                )
            return False

        except Exception as e:
            self._logger.exception(
                "%s Unexpected error sending message `%s` (%s: %s)",
                self._gateway.log_id,
                message,
                type(e).__name__,
                e
            )
            return False
