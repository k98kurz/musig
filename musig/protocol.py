from __future__ import annotations
from base64 import b64decode
from enum import Enum
from math import ceil, log2
from musig import Nonce, NonceCommitment, PartialSignature, Signature
from musig.abstractclasses import AbstractProtocolMessage
from musig.helpers import bytes_are_same
from nacl.signing import SigningKey, VerifyKey, SignedMessage as NaclSignedMessage
from uuid import UUID


class ProtocolState(Enum):
    """An enum containing all of the byte representations of possible protocol
        states as encoded in ProtocolMessage or referenced in SigningSession.
    """
    EMPTY = 0x00
    INITIALIZED = 0x10

    AWAITING_PARTICIPANT_KEY = 0x11
    SENDING_PARTICIPANT_KEY = 0x12
    ACK_PARTICIPANT_KEY = 0x13
    REJECT_PARTICIPANT_KEY = 0x1f

    AWAITING_COMMITMENT = 0x20
    SENDING_COMMITMENT = 0x21
    ACK_COMMITMENT = 0x22
    TIME_EXCEEDED_AWAITING_COMMITMENT = 0x2e
    REJECT_COMMITMENT = 0x2f

    AWAITING_MESSAGE = 0x30
    SENDING_MESSAGE = 0x31
    ACK_MESSAGE = 0x32
    REJECT_MESSAGE = 0x3f

    AWAITING_NONCE = 0x40
    SENDING_NONCE = 0x41
    ACK_NONCE = 0x42
    TIME_EXCEEDED_AWAITING_NONCE = 0x4e
    REJECT_NONCE = 0x4f

    AWAITING_PARTIAL_SIGNATURE = 0x50
    SENDING_PARTIAL_SIGNATURE = 0x51
    ACK_PARTIAL_SIGNATURE = 0x52
    TIME_EXCEEDED_AWAITING_PARTIAL_SIGNATURE = 0x5e
    REJECT_PARTIAL_SIGNATURE = 0x5f

    COMPLETED = 0xe0
    ABORTED = 0xff


class ProtocolError(Exception):
    """A custom error to be thrown if the SigningSession is configured to throw them."""
    def __init__(self, message: str, protocol_state: ProtocolState) -> None:
        self.message = message
        self.protocol_state = protocol_state
        super().__init__(message)

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on instance; i.e. serialize to bytes."""
        return self.protocol_state.value.to_bytes(1, 'little') + bytes(self.message, 'utf-8')

    def __str__(self) -> str:
        """Result of calling str() on an instance."""
        return self.protocol_state.name + ':' + self.message

    def __eq__(self, other) -> bool:
        """Timing-attack safe comparison."""
        if not isinstance(other, self.__class__):
            return False
        return bytes_are_same(bytes(self), bytes(other))

    def __hash__(self) -> int:
        """Result of calling hash() on instance; allows inclusion in sets and
            use as a key in a dict (of dubious worth, but technically possible.)
        """
        return hash(bytes(self))

    @classmethod
    def from_bytes(cls, bts: bytes) -> ProtocolError:
        """Deserializes output from __bytes__."""
        protocol_state = ProtocolState(bts[0])
        message = str(bts[1:], 'utf-8')
        return cls(message, protocol_state)

    @classmethod
    def from_str(cls, s: str) -> ProtocolError:
        """Deserializes output from __str__."""
        parts = s.split(':')
        protocol_state = ProtocolState[parts[0]]
        message = ':'.join(parts[1:])
        return cls(message, protocol_state)


class ProtocolMessage(AbstractProtocolMessage):
    """A class that handles packing and unpacking messages for mediating the
        protocol. This should be sufficient, but any other system can be used as
        long as the SigningSession methods are called in the right manner and
        the right data is communicated between parties in the right order.
        Multiple serialization options are available for convenience.
    """
    def __init__(self, data: dict = None) -> None:
        """Initialize with json.loads output of json.dumps serialization to
            restore an instance. Otherwise, it is better to use the create method.
        """
        if data is None:
            raise ValueError('cannot initialize an empty ProtocolMessage')
        if not isinstance(data, dict):
            raise TypeError('cannot initialize with non-dict data')
        if 'state' not in data or 'message' not in data:
            raise ValueError('must include a valid state and message to initialize')

        # parse session_id
        if 'session_id' in data:
            session_id = data['session_id'] if type(data['session_id']) is bytes else b64decode(data['session_id'])
            self.session_id = UUID(bytes=session_id)

        # parse state
        self.state = ProtocolState[data['state']]

        # parse message
        self.message = data['message'] if type(data['message']) is bytes else b64decode(data['message'])
        self.parse_message()

        # parse signature if present
        if 'signature' in data:
            sig = data['signature'] if type(data['signature']) is bytes else b64decode(data['signature'])
            sig = sig[:64]
            msg = self.state.value.to_bytes(1, 'little') + self.message
            self.signature = NaclSignedMessage._from_parts(sig, msg, sig+msg)

        # parse vkey if present
        if 'vkey' in data:
            self.vkey = VerifyKey(data['vkey'] if type(data['vkey']) is bytes else b64decode(data['vkey']))

    def __bytes__(self) -> bytes:
        """Serialize to bytes using custom (but simple) serialization scheme."""
        bta = bytearray()

        # first serializse the state
        bta.append(self.state.value)

        # next serialize the session_id
        if self.state is not ProtocolState.EMPTY:
            bta.extend(self.session_id.bytes)

        # serialize each message element to bytes
        m = self.message if type(self.message) is bytes else bytes(self.message)
        # only serialize if it has a length
        if len(m) > 0:
            # code for message
            bta.extend(b'm')
            # length of the message length
            m_len_len = ceil(log2(len(m) + 1) / 8)
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
            # code for vkey
            bta.extend(b'v')
            # byte encoding of vkey is always 32 bytes
            bta.extend(bytes(self.vkey))

        return bytes(bta)

    @classmethod
    def from_bytes(cls, data: bytes) -> ProtocolMessage:
        """Deserialize from bytes using custom (but simple) serialization scheme."""
        if type(data) not in (bytes, bytearray):
            raise TypeError('supplied data must be of type bytes or bytearray')

        # first parse the protocol state
        state = ProtocolState(data[0])
        data = data[1:]

        message = b''
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
                message = m
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
            'message': message
        }

        if session_id is not None:
            param['session_id'] = session_id

        if signature is not None:
            param['signature'] = signature

        if vkey is not None:
            param['vkey'] = vkey

        return cls(param)

    def parse_message(self) -> None:
        """Parses the message into parts based upon protocol state, e.g. lists
            of participant keys, nonces, nonce commitments, etc, storing the
            result in self.message_parts/self['message_parts'].
        """
        parts = []
        message = self.message
        if self.state in (
                            ProtocolState.SENDING_PARTICIPANT_KEY,
                            ProtocolState.ACK_PARTICIPANT_KEY,
                            ProtocolState.REJECT_PARTICIPANT_KEY,
                            ProtocolState.AWAITING_COMMITMENT,
                            ProtocolState.AWAITING_NONCE,
                            ProtocolState.AWAITING_PARTIAL_SIGNATURE,
                        ):
            # every 32 bytes will be a VerifyKey
            while len(message) > 0:
                parts.append(VerifyKey(message[:32]))
                message = message[32:]

        if self.state in (
                            ProtocolState.SENDING_COMMITMENT,
                            ProtocolState.ACK_COMMITMENT,
                            ProtocolState.REJECT_COMMITMENT,
                        ):
            # every 32 bytes will be a NonceCommitment
            while len(message) > 0:
                parts.append(NonceCommitment.from_bytes(message[:32]))
                message = message[32:]

        if self.state in (
                            ProtocolState.SENDING_NONCE,
                            ProtocolState.ACK_NONCE,
                            ProtocolState.REJECT_NONCE,
                        ):
            # every 32 bytes will be a Nonce
            while len(message) > 0:
                parts.append(Nonce.from_bytes(message[:32]))
                message = message[32:]

        if self.state in (
                            ProtocolState.SENDING_PARTIAL_SIGNATURE,
                            ProtocolState.ACK_PARTIAL_SIGNATURE,
                            ProtocolState.REJECT_PARTIAL_SIGNATURE,
                        ):
            # every 32 bytes will be a PartialSignature
            while len(message) > 0:
                parts.append(PartialSignature.from_bytes(message[:32]))
                message = message[32:]

        if self.state is ProtocolState.COMPLETED:
            parts = [Signature.from_bytes(message)]

        if self.state is ProtocolState.ABORTED:
            parts = [ProtocolError.from_bytes(message)]

        self.message_parts = parts

    def add_signature(self, skey: SigningKey) -> ProtocolMessage:
        """Add a signature to the message using the provided SigningKey. This
            signs the protocol state + message, attaching the signature and the
            relevant VerifyKey to the instance.
        """
        self.signature = skey.sign(self.state.value.to_bytes(1, 'little') + self.message)
        self.vkey = skey.verify_key
        return self

    def check_signature(self) -> bool:
        """Return true if and only if the instance contains a VerifyKey and a
            signature valid for the protocol state + message, else return False.
        """
        try:
            if self.signature is None or self.vkey is None:
                return False
            self.vkey.verify(self.signature)
            return True
        except:
            return False

    @classmethod
    def create(cls, id: UUID|None, state: ProtocolState, data: list) -> ProtocolMessage:
        """Create a new instance with the given id, state, and data.
            If the state is EMPTY, the id is ignored.

            If the state is SENDING_PARTICIPANT_KEY, ACK_PARTICIPANT_KEY,
            REJECT_PARTICIPANT_KEY, AWAITING_COMMITMENT, AWAITING_NONCE, or
            AWAITING_PARTIAL_SIGNATURE, the data must be a list of
            VerifyKey|bytes.

            If the state is SENDING_COMMITMENT, ACK_COMMITMENT, or
            REJECT_COMMITMENT, the data must be a list of NonceCommitment|bytes.

            If the state is SENDING_MESSAGE, ACK_MESSAGE, or REJECT_MESSAGE, the
            data must be a list of str|bytes.

            If the state is SENDING_NONCE, ACK_NONCE, or REJECT_NONCE, the data
            must be a list of Nonce|bytes.

            If the state is SENDING_PARTIAL_SIGNATURE, ACK_PARTIAL_SIGNATURE, or
            REJECT_PARTIAL_SIGNATURE, the data must be a list of
            PartialSignature|bytes.

            If the state is COMPLETED, the data must be a Signature|bytes.

            If the state is ABORTED, the data must be a ProtocolError|bytes.
        """
        if not isinstance(id, UUID) and state is not ProtocolState.EMPTY:
            raise TypeError('id must be a valid UUID for non-EMPTY state')

        if not isinstance(state, ProtocolState):
            raise TypeError('state must be a valid ProtocolState')

        if type(data) not in (list, tuple):
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
                'session_id': id.bytes,
                'state': state.name,
                'message': ''
            })

        if state in (
                        ProtocolState.SENDING_PARTICIPANT_KEY,
                        ProtocolState.ACK_PARTICIPANT_KEY,
                        ProtocolState.REJECT_PARTICIPANT_KEY,
                        ProtocolState.AWAITING_COMMITMENT,
                        ProtocolState.AWAITING_NONCE,
                        ProtocolState.AWAITING_PARTIAL_SIGNATURE,
                    ):
            for vk in data:
                if not isinstance(vk, VerifyKey) and (type(vk) is not bytes or len(vk) != 32):
                    raise TypeError(f'each datum for ProtocolMessage with state={state.name} must be VerifyKey or 32 bytes')
            vkeys = [vk if type(vk) is bytes else bytes(vk) for vk in data]
            return cls({
                'session_id': id.bytes,
                'state': state.name,
                'message': b''.join(vkeys)
            })

        if state in (
                        ProtocolState.SENDING_COMMITMENT,
                        ProtocolState.ACK_COMMITMENT,
                        ProtocolState.REJECT_COMMITMENT,
                    ):
            for nc in data:
                if not isinstance(nc, NonceCommitment) and (type(nc) is not bytes or len(nc) != 32):
                    raise TypeError(f'each datum for ProtocolMessage with state={state.name} must be NonceCommitment or 32 bytes')
            commitments = [nc if type(nc) is bytes else bytes(nc) for nc in data]
            return cls({
                'session_id': id.bytes,
                'state': state.name,
                'message': b''.join(commitments)
            })

        if state in (
                        ProtocolState.SENDING_MESSAGE,
                        ProtocolState.ACK_MESSAGE,
                        ProtocolState.REJECT_MESSAGE,
                    ):
            if not type(data[0]) in (str, bytes):
                raise TypeError(f'datum for ProtocolMessage with state={state.name} must be str or bytes')
            msg = data[0] if type(data[0]) is bytes else bytes(data[0])
            return cls({
                'session_id': id.bytes,
                'state': state.name,
                'message': msg
            })

        if state in (
                        ProtocolState.SENDING_NONCE,
                        ProtocolState.ACK_NONCE,
                        ProtocolState.REJECT_NONCE,
                    ):
            for n in data:
                if not isinstance(n, Nonce) and (type(n) is not bytes or len(n) != 32):
                    raise TypeError(f'each datum for ProtocolMessage with state={state.name} must be Nonce or 32 bytes')
            nonces = [n if type(n) is bytes else bytes(n) for n in data]
            return cls({
                'session_id': id.bytes,
                'state': state.name,
                'message': b''.join(nonces)
            })

        if state in (
                        ProtocolState.SENDING_PARTIAL_SIGNATURE,
                        ProtocolState.ACK_PARTIAL_SIGNATURE,
                        ProtocolState.REJECT_PARTIAL_SIGNATURE,
                    ):
            for s in data:
                if not isinstance(s, PartialSignature) and (type(s) is not bytes or len(s) != 32):
                    raise TypeError(f'each datum for ProtocolMessage with state={state.name} must be PartialSignature or 32 bytes')
            sigs = [s if type(s) is bytes else bytes(s.public()) for s in data]
            return cls({
                'session_id': id.bytes,
                'state': state.name,
                'message': b''.join(sigs)
            })

        if state is ProtocolState.COMPLETED:
            if not isinstance(data[0], Signature) and (type(data[0]) is not bytes or len(data[0]) < 65):
                raise TypeError(f'datum for ProtocolMessage with state={state.name} must be Siganture or > 64 bytes')
            sig = data[0] if type(data[0]) is bytes else bytes(data[0])
            return cls({
                'session_id': id.bytes,
                'state': state.name,
                'message': bytes(sig)
            })

        if state is ProtocolState.ABORTED:
            if not isinstance(data[0], ProtocolError) and (type(data[0]) is not bytes or len(data[0]) < 1):
                raise TypeError(f'each datum for ProtocolMessage with state={state.name} must be ProtocolError or >0 bytes')
            err = data[0] if type(data[0]) is bytes else bytes(data[0])
            return cls({
                'session_id': id.bytes,
                'state': state.name,
                'message': err
            })

    # properties
    @property
    def session_id(self) -> UUID|None:
        """The UUID of the signing session for which this message was constructed."""
        return self._session_id if hasattr(self, '_session_id') else None

    @session_id.setter
    def session_id(self, data: UUID):
        """The UUID of the signing session for which this message was constructed."""
        if type(data) not in (UUID, bytes):
            raise TypeError('session_id must be UUID or bytes')

        self['session_id'] = data if type(data) is bytes else data.bytes
        self._session_id = UUID(bytes=data) if type(data) is bytes else data

    @property
    def state(self) -> ProtocolState:
        """The protocol state of the message."""
        return self._state if hasattr(self, '_state') else None

    @state.setter
    def state(self, data: ProtocolState):
        """The protocol state of the message."""
        if type(data) is not ProtocolState:
            raise TypeError('state must be ProtocolState')

        self['state'] = data.name
        self._state = data

    @property
    def message(self) -> bytes:
        """The message itself."""
        return self._message if hasattr(self, '_message') else None

    @message.setter
    def message(self, data: bytes):
        """The message itself."""
        if type(data) not in (bytes, str):
            raise TypeError('message must be bytes or str')

        self['message'] = data if type(data) is bytes else bytes(data, 'utf-8')

    @property
    def message_parts(self) -> tuple:
        """The things that serialize into and deserialize from self.message."""
        return self._message_parts if hasattr(self, '_message_parts') else tuple()

    @message_parts.setter
    def message_parts(self, data: tuple):
        """The things that serialize into and deserialize from self.message."""
        if type(data) not in (tuple, list):
            raise TypeError('message_parts must be list or tuple of values')

        self['message_parts'] = tuple(data)

    @property
    def signature(self) -> NaclSignedMessage|None:
        """The Signature result of add_signature."""
        return self._signature if hasattr(self, '_signature') else None

    @signature.setter
    def signature(self, data: NaclSignedMessage):
        """The Signature result of add_signature."""
        if type(data) is not NaclSignedMessage:
            raise TypeError('signature must be nacl.signing.SignedMessage')

        self['signature'] = data

    @property
    def vkey(self) -> VerifyKey|None:
        """The VerifyKey used to verify the signature."""
        return self._vkey if hasattr(self, '_vkey') else None

    @vkey.setter
    def vkey(self, data: VerifyKey):
        """The VerifyKey used to verify the signature."""
        if type(data) is not VerifyKey:
            raise TypeError('vkey must be VerifyKey')

        self['vkey'] = data
