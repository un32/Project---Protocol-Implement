import struct
import time
import hashlib
import secrets
from enum import IntEnum
from dataclasses import dataclass

#Protocol constant
PROTOCOL_VERSION = 0x01
HEADER_SIZE = 16
DEFAULT_PORT = 8888

class MessageType(IntEnum):
    """SGCP Message Types"""
    # Connection management
    MSG_HELLO = 0x01
    MSG_AUTH_REQUEST = 0x02
    MSG_AUTH_RESPONSE = 0x03
    MSG_CAPABILITIES = 0x04
    MSG_DISCONNECT = 0x05
    MSG_KEEPALIVE = 0x06
    
    # Group management
    MSG_GROUP_CREATE = 0x10
    MSG_GROUP_JOIN = 0x11
    MSG_GROUP_LEAVE = 0x12
    MSG_GROUP_INFO = 0x13
    MSG_GROUP_LIST = 0x14
    
    # Messaging
    MSG_CHAT = 0x20
    MSG_PRIVATE = 0x21
    
    # User management
    MSG_USER_STATUS = 0x30
    MSG_USER_INFO = 0x31
    MSG_USER_LIST = 0x32
    
    # File transfer
    MSG_FILE_OFFER = 0x40
    MSG_FILE_REQUEST = 0x41
    MSG_FILE_DATA = 0x42
    
    # Status and errors
    MSG_ACK = 0xF0
    MSG_ERROR = 0xFF

class MessageFlags(IntEnum):
    # SGCP Message Flags
    FLAG_NONE = 0x00
    FLAG_ENCRYPTED = 0x01
    FLAG_COMPRESSED = 0x02
    FLAG_URGENT = 0x04
    FLAG_REQUIRES_ACK = 0x08
    FLAG_FRAGMENTED = 0x10
    FLAG_LAST_FRAGMENT = 0x20

class ErrorCode(IntEnum):
    # SGCP Error Codes
    ERR_NONE = 0x00
    ERR_INVALID_MESSAGE = 0x01
    ERR_AUTH_FAILED = 0x02
    ERR_PERMISSION_DENIED = 0x03
    ERR_USER_NOT_FOUND = 0x04
    ERR_GROUP_NOT_FOUND = 0x05
    ERR_VERSION_MISMATCH = 0x06
    ERR_RESOURCE_LIMIT = 0x07
    ERR_ALREADY_EXISTS = 0x08
    ERR_INTERNAL_ERROR = 0xFF

class ProtocolState(IntEnum):
   # SGCP Protocol States (DFA)
    STATE_DISCONNECTED = 0x00
    STATE_CONNECTING = 0x01
    STATE_HELLO_SENT = 0x02
    STATE_CAPABILITY_NEGO = 0x03
    STATE_AUTHENTICATING = 0x04
    STATE_AUTHENTICATED = 0x05
    STATE_ACTIVE = 0x06
    STATE_ERROR = 0x07
    STATE_DISCONNECTING = 0x08

class Capabilities(IntEnum):
    # SGCP Capabilities
    CAP_BASIC_CHAT = 0x00000001
    CAP_FILE_TRANSFER = 0x00000002
    CAP_ENCRYPTION = 0x00000004
    CAP_COMPRESSION = 0x00000008

@dataclass
class SGCPHeader:
    #SGCP Message Header Structure
    version: int
    message_type: int
    payload_length: int
    sequence_number: int
    timestamp: int
    flags: int
    reserved: bytes

class SGCPMessage:
    #SGCP Message Handler
    
    def __init__(self, msg_type: MessageType, payload: bytes = b'', flags: MessageFlags = MessageFlags.FLAG_NONE):
        self.header = SGCPHeader(
            version=PROTOCOL_VERSION,
            message_type=msg_type,
            payload_length=len(payload),
            sequence_number=0,
            timestamp=int(time.time()),
            flags=flags,
            reserved=b'\x00\x00\x00'
        )
        self.payload = payload
    
    def set_sequence_number(self, seq_num: int):
       # Set sequence number for the message
        self.header.sequence_number = seq_num
    
    def serialize(self) -> bytes:
        # Serialize message to bytes for transmission
        header_bytes = struct.pack(
            '!BBHIIB3s',
            self.header.version,
            self.header.message_type,
            self.header.payload_length,
            self.header.sequence_number,
            self.header.timestamp,
            self.header.flags,
            self.header.reserved
        )
        return header_bytes + self.payload
    
    @classmethod
    def deserialize(cls, data: bytes):
        # Deserialize bytes to SGCPMessage
        if len(data) < HEADER_SIZE:
            raise ValueError("Insufficient data for header")
        
        header_data = struct.unpack('!BBHIIB3s', data[:HEADER_SIZE])
        header = SGCPHeader(*header_data)
        
        if len(data) < HEADER_SIZE + header.payload_length:
            raise ValueError("Insufficient data for payload")
        
        payload = data[HEADER_SIZE:HEADER_SIZE + header.payload_length]
        
        msg = cls(MessageType(header.message_type), payload, MessageFlags(header.flags))
        msg.header = header
        return msg

