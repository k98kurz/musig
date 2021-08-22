from __future__ import annotations
from base64 import b64encode, b64decode
from enum import Enum
from hashlib import new
from math import ceil, log2
from musig.helpers import bytes_are_same
from musig import Nonce, NonceCommitment, PartialSignature, Signature
from nacl.signing import SigningKey, VerifyKey, SignedMessage as NaclSignedMessage
from uuid import UUID


class ProtocolState(Enum):
    """An enum containing all of the byte representations of possible protocol
        states as encoded in ProtocolMessage or referenced in SigningSession.
    """
    EMPTY = 0x00
    INITIALIZED = 0x10
    AWAITING_PARTICIPANT_KEY = 0x11
    ACK_PARTICIPANT_KEY = 0x12
    REJECT_PARTICIPANT_KEY = 0x1f
    AWAITING_COMMITMENT = 0x20
    ACK_COMMITMENT = 0x21
    TIME_EXCEEDED_AWAITING_COMMITMENT = 0x2e
    REJECT_COMMITMENT = 0x2f
    SENDING_COMMITMENT = 0x30
    AWAITING_MESSAGE = 0x40
    ACK_MESSAGE = 0x41
    REJECT_MESSAGE = 0x4f
    SENDING_MESSAGE = 0x50
    AWAITING_NONCE = 0x60
    ACK_NONCE = 0x61
    TIME_EXCEEDED_AWAITING_NONCE = 0x6e
    REJECT_NONCE = 0x6f
    SENDING_NONCE = 0x70
    AWAITING_PARTIAL_SIGNATURE = 0x80
    ACK_PARTIAL_SIGNATURE = 0x81
    TIME_EXCEEDED_AWAITING_PARTIAL_SIGNATURE = 0x8e
    REJECT_PARTIAL_SIGNATURE = 0x8f
    SENDING_PARTIAL_SIGNATURE = 0x90
    COMPLETED = 0xe0
    ABORTED = 0xff


class ProtocolError(Exception):
    """A custom error to be thrown if the SigningSession is configured to throw them."""
    def __init__(self, message: str, protocol_state: ProtocolState) -> None:
        self.message = message
        self.protocol_state = protocol_state
        super().__init__(message)

    def __bytes__(self) -> bytes:
        return self.protocol_state.value.to_bytes(1, 'little') + bytes(self.message, 'utf-8')

    def __eq__(self, other) -> bool:
        return self.message == other.message and self.protocol_state is other.protocol_state

    def __hash__(self) -> int:
        return int.from_bytes(new('shake256', bytes(self)).digest(12), 'little')

    @classmethod
    def from_bytes(cls, bts: bytes) -> ProtocolError:
        protocol_state = ProtocolState(bts[0])
        message = str(bts[1:], 'utf-8')
        return cls(message, protocol_state)


class ProtocolMessage(dict):
    """A class that handles packing and unpacking messages for mediating the
        protocol. This should be sufficient, but any other system can be used as
        long as the SigningSession methods are called in the right manner and
        the right data is communicated between parties in the right order.
        Multiple serialization options are available for convenience.
    """
    def __init__(self, data: dict = None) -> None:
        if data is None:
            raise ValueError('cannot initialize an empty ProtocolMessage')
        if not isinstance(data, dict):
            raise TypeError('cannot initialize with non-dict data')
        if 'state' not in data or 'message' not in data:
            raise ValueError('must include a valid state and message to initialize')

        # initialize key:value pairs with input dict
        super().__init__(data)

        # parse session_id
        if 'session_id' in self:
            self._session_id = UUID(bytes=b64decode(self['session_id']))

        # parse state
        self._state = ProtocolState[self['state']]

        # parse message
        self.parse_message()

        # parse signature if present
        if 'signature' in self:
            sig = b64decode(self['signature'])
            msg = bytes(self)
            self._signature = NaclSignedMessage._from_parts(sig, msg, sig+msg)

        # parse vkey if present
        if 'vkey' in self:
            self._vkey = VerifyKey(b64decode(self['vkey']))

    def __bytes__(self) -> bytes:
        """Serialize to bytes using custom (but simple) serialization scheme."""
        bta = bytearray()

        # first serializse the state
        bta.append(self._state.value)

        # next serialize the session_id
        if self.state is not ProtocolState.EMPTY:
            bta.extend(self._session_id.bytes)

        # serialize each message line
        for m in self._message:
            # serialize each message element to bytes
            m = m if type(m) is bytes else bytes(m)
            # only serialize if it has a length
            if len(m) > 0:
                # code for message line
                bta.extend(b'm')
                # length of the message length
                m_len_len = ceil(log2(len(m)) / 8)
                bta.append(m_len_len)
                # message length
                m_len = len(m).to_bytes(m_len_len, 'little')
                bta.extend(m_len)
                # message
                bta.extend(m)

        # encode the signature if it is set
        if self.signature is not None:
            # code for signature
            bta.extend(b's')
            # byte encoding of signature always has len 64
            bta.extend(self.signature.signature)

        # encode the vkey if it is set
        if self.vkey is not None:
            # core for vkey
            bta.extend(b'v')
            # byte encoding of vkey is always 32 bytes
            bta.extend(bytes(self.vkey))

        return bytes(bta)

    def __eq__(self, other) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return bytes_are_same(bytes(self), bytes(other))

    @classmethod
    def from_bytes(cls, data: bytes) -> ProtocolMessage:
        """Deserialize from bytes using custom (but simple) serialization scheme."""
        if type(data) not in (bytes, bytearray):
            raise TypeError('supplied data must be of type bytes or bytearray')

        # first parse the protocol state
        state = ProtocolState(data[0])
        data = data[1:]

        message = []
        session_id = None
        signature = None
        vkey = None

        # now the session_id if applicable
        if state is not ProtocolState.EMPTY:
            session_id = data[:16]
            data = data[16:]

        # parse each section of the message
        while len(data) > 0:
            code = data[0:1]
            data = data[1:]

            # parse a message
            if code == b'm':
                # length of message length
                m_len_len = data[0]
                # message length
                m_len = int.from_bytes(data[1:1+m_len_len], 'little')
                # message
                m = data[1+m_len_len:1+m_len_len+m_len]
                message.append(m)
                # remove from data
                data = data[1+m_len_len+m_len:]

            # parse a signature
            if code == b's':
                # signature is always 64 bytes
                signature = data[:64]
                data = data[64:]

            # parse a vkey
            if code == b'v':
                # vkey is always 32 bytes
                vkey = data[:32]
                data = data[32:]

        # instantiate
        param = {
            'state': state.name,
            'message': '.'.join([b64encode(m).decode() for m in message])
        }

        if session_id is not None:
            param['session_id'] = b64encode(session_id).decode()

        if signature is not None:
            param['signature'] = b64encode(signature).decode()

        if vkey is not None:
            param['vkey'] = b64encode(vkey).decode()

        return cls(param)

    def __str__(self) -> str:
        return bytes(self).hex()

    def parse_message(self) -> None:
        """Handles parsing the message based upon the ProtocolState."""
        self._message = [b64decode(m) for m in self['message'].split('.')]

        if self.state in (
                            ProtocolState.ACK_PARTICIPANT_KEY,
                            ProtocolState.REJECT_PARTICIPANT_KEY,
                            ProtocolState.AWAITING_COMMITMENT,
                            ProtocolState.AWAITING_NONCE,
                            ProtocolState.AWAITING_PARTIAL_SIGNATURE,
                        ):
            self._message = [VerifyKey(vk) for vk in self._message]

        if self.state in (
                            ProtocolState.ACK_COMMITMENT,
                            ProtocolState.REJECT_COMMITMENT,
                            ProtocolState.SENDING_COMMITMENT,
                        ):
            self._message = [NonceCommitment(nc) for nc in self._message]

        if self.state in (
                            ProtocolState.ACK_NONCE,
                            ProtocolState.REJECT_NONCE,
                            ProtocolState.SENDING_NONCE,
                        ):
            self._message = [Nonce(nc) for nc in self._message]

        if self.state in (
                            ProtocolState.ACK_PARTIAL_SIGNATURE,
                            ProtocolState.REJECT_PARTIAL_SIGNATURE,
                            ProtocolState.SENDING_PARTIAL_SIGNATURE,
                        ):
            self._message = [PartialSignature(s) for s in self._message]

        if self.state is ProtocolState.COMPLETED:
            self._message = [Signature(s) for s in self._message]

        if self.state is ProtocolState.ABORTED:
            self._message = [ProtocolError.from_bytes(e) for e in self._message]

    def add_signature(self, skey: SigningKey) -> ProtocolMessage:
        self._signature = skey.sign(bytes(self))
        self['signature'] = b64encode(self._signature.signature).decode()
        self._vkey = skey.verify_key
        self['vkey'] = b64encode(bytes(self._vkey)).decode()
        return self

    def check_signature(self) -> bool:
        try:
            if self.signature is None or self.vkey is None:
                return False
            self.vkey.verify(self.signature)
            return True
        except:
            return False

    @classmethod
    def from_str(cls, data: str) -> ProtocolMessage:
        return cls.from_bytes(bytes.fromhex(data))

    @classmethod
    def create(cls, id: UUID, state: ProtocolState, data: list) -> ProtocolMessage:
        if not isinstance(id, UUID) and state is not ProtocolState.EMPTY:
            raise TypeError('id must be a valid UUID for non-EMPTY state')

        if not isinstance(state, ProtocolState):
            raise TypeError('state must be a valid ProtocolState')

        if not isinstance(data, list) and not isinstance(data, tuple):
            raise TypeError('data must be a list or tuple of values')

        if state is ProtocolState.EMPTY:
            return cls({
                'state': state.name,
                'message': ''
            })

        if state in (
                        ProtocolState.INITIALIZED,
                        ProtocolState.AWAITING_MESSAGE,
                        ProtocolState.AWAITING_PARTICIPANT_KEY,
                    ):
            return cls({
                'session_id': b64encode(id.bytes).decode(),
                'state': state.name,
                'message': ''
            })

        if state in (
                        ProtocolState.ACK_PARTICIPANT_KEY,
                        ProtocolState.REJECT_PARTICIPANT_KEY,
                        ProtocolState.AWAITING_COMMITMENT,
                        ProtocolState.AWAITING_NONCE,
                        ProtocolState.AWAITING_PARTIAL_SIGNATURE,
                    ):
            vkeys = [vk if type(vk) is bytes else bytes(vk) for vk in data]
            vkeys = [b64encode(vk).decode() for vk in vkeys]
            return cls({
                'session_id': b64encode(id.bytes).decode(),
                'state': state.name,
                'message': '.'.join(vkeys)
            })

        if state in (
                        ProtocolState.ACK_COMMITMENT,
                        ProtocolState.REJECT_COMMITMENT,
                        ProtocolState.SENDING_COMMITMENT
                    ):
            commitments = [nc if isinstance(nc, NonceCommitment) else NonceCommitment(nc) for nc in data]
            commitments = [b64encode(bytes(nc)).decode() for nc in commitments]
            return cls({
                'session_id': b64encode(id.bytes).decode(),
                'state': state.name,
                'message': '.'.join(commitments)
            })

        if state in (
                        ProtocolState.ACK_MESSAGE,
                        ProtocolState.REJECT_MESSAGE,
                        ProtocolState.SENDING_MESSAGE,
                    ):
            msg = data[0] if type(data[0]) is bytes else bytes(data[0])
            return cls({
                'session_id': b64encode(id.bytes).decode(),
                'state': state.name,
                'message': b64encode(msg).decode()
            })

        if state in (
                        ProtocolState.ACK_NONCE,
                        ProtocolState.REJECT_NONCE,
                        ProtocolState.SENDING_NONCE,
                    ):
            nonces = [n if isinstance(n, Nonce) else Nonce(n) for n in data]
            nonces = [b64encode(bytes(n)).decode() for n in nonces]
            return cls({
                'session_id': b64encode(id.bytes).decode(),
                'state': state.name,
                'message': '.'.join(nonces)
            })

        if state in (
                        ProtocolState.ACK_PARTIAL_SIGNATURE,
                        ProtocolState.REJECT_PARTIAL_SIGNATURE,
                        ProtocolState.SENDING_PARTIAL_SIGNATURE,
                    ):
            sigs = [s if isinstance(s, PartialSignature) else PartialSignature(s) for s in data]
            sigs = [b64encode(bytes(s)).decode() for s in sigs]
            return cls({
                'session_id': b64encode(id.bytes).decode(),
                'state': state.name,
                'message': '.'.join(sigs)
            })

        if state is ProtocolState.COMPLETED:
            sig = data[0] if isinstance(data[0], Signature) else Signature(data[0])
            return cls({
                'session_id': b64encode(id.bytes).decode(),
                'state': state.name,
                'message': b64encode(bytes(sig)).decode()
            })

        if state is ProtocolState.ABORTED:
            err = data[0] if isinstance(data[0], ProtocolError) else ProtocolError.from_bytes(data[0])
            return cls({
                'session_id': b64encode(id.bytes).decode(),
                'state': state.name,
                'message': b64encode(bytes(err)).decode()
            })

    # properties
    session_id = property(lambda self: self._session_id if hasattr(self, '_session_id') else None)
    state = property(lambda self: self._state if hasattr(self, '_state') else None)
    message = property(lambda self: self._message if hasattr(self, '_message') else None)
    signature = property(lambda self: self._signature if hasattr(self, '_signature') else None)
    vkey = property(lambda self: self._vkey if hasattr(self, '_vkey') else None)
