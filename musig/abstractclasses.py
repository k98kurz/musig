from __future__ import annotations
from abc import abstractmethod
from base64 import b64encode
from enum import EnumMeta
from musig import bytes_are_same
from nacl.signing import SigningKey, VerifyKey
from uuid import UUID


class ExtendedDict(dict):
    """ExtendedDict handles some serialization/deserialization."""
    def __setitem__(self, key, value) -> None:
        """Method that is called when `instance[key]=value` is used.
            Any key that is not a property of the instance will not be set.
            Any key that is set will have its values encoded to be maximally
            compatible with json serialization.
        """
        if hasattr(self, key):
            setattr(self, f'_{key}', value)
            if type(value) in (int, str):
                super().__setitem__(key, value)
            elif type(value) is bytes:
                super().__setitem__(key, b64encode(value).decode())
            elif type(value) in (tuple, list):
                val = []
                for item in value:
                    if type(item) in (int, str):
                        val.append(item)
                    else:
                        val.append(b64encode(item if type(item) is bytes else bytes(item)).decode())
                super().__setitem__(key, tuple(val))
            elif type(value) is dict:
                nv = {}
                for name in value:
                    val = value[name]
                    if type(name) not in (str, int):
                        name = b64encode(name if type(name) is bytes else bytes(name)).decode()
                    if type(val) not in (str, int):
                        val = b64encode(val if type(val) is bytes else bytes(val)).decode()
                    nv[name] = val
                super().__setitem__(key, nv)
            else:
                super().__setitem__(key, b64encode(bytes(value)).decode())

    @abstractmethod
    def __bytes__(self) -> bytes:
        """Result of calling bytes() on instance; i.e. serializes instance as
            bytes. Must be implemented for __str__ and from_str to function.
        """
        ...

    def __str__(self) -> str:
        """Result of calling str() on instance; serializes instance as a
            hexidecimal str based upon the bytes serialization. Relies upon
            __bytes__ to function.
        """
        return bytes(self).hex()

    def __hash__(self) -> int:
        """Result of calling hash() on instance; allows inclusion in sets and
            use as a key in a dict (of dubious worth, but technically possible.)
        """
        return hash(bytes(self))

    def __eq__(self, other) -> bool:
        """Timing-attack safe comparison."""
        if not isinstance(other, self.__class__):
            return False
        return bytes_are_same(bytes(self), bytes(other))

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> ExtendedDict:
        """Deserializes output from __bytes__. Must be implemented for from_str
            to function.
        """
        ...

    @classmethod
    def from_str(cls, data: str) -> ExtendedDict:
        """Deserializes output from __str__, i.e. hexidecimal str of __bytes__
            output. Relies upon from_bytes to function.
        """
        return cls.from_bytes(bytes.fromhex(data))


class AbstractNonce(ExtendedDict):
    @abstractmethod
    def __add__(self, other: AbstractNonce) -> AbstractNonce:
        ...

    @abstractmethod
    def copy(self) -> AbstractNonce:
        """Make a copy of the instance. Heavily dependent upon the __init__ definition."""
        ...

    @abstractmethod
    def public(self) -> AbstractNonce:
        """Return a copy of the instance with only the public point value (R)."""
        ...

    @property
    @abstractmethod
    def r(self) -> bytes:
        """The private scalar value."""
        ...

    @property
    @abstractmethod
    def R(self) -> bytes:
        """The public point value."""
        ...


class AbstractNonceCommitment(ExtendedDict):
    @classmethod
    @abstractmethod
    def create(cls, nonce: AbstractNonce) -> AbstractNonceCommitment:
        """Create a new instance by hashing the given nonce."""
        ...

    @abstractmethod
    def copy(self) -> AbstractNonceCommitment:
        """Make a copy of the instance. Heavily dependent upon the __init__ definition."""
        ...

    @abstractmethod
    def is_valid_for(self, nonce: AbstractNonce) -> bool:
        """Check if the current instance is a valid commitment for a given nonce."""
        ...

    @property
    def HR(self) -> bytes:
        """The nonce commitment bytes (hash of a nonce point)."""
        ...


class AbstractPartialSignature(ExtendedDict):
    @classmethod
    def create(cls, skey: SigningKey, r: bytes, L: bytes, X: AbstractPublicKey,
            R: bytes, M: bytes) -> dict:
        """Create a new instance using the SigningKey of the participant (skey),
            from which the private key will be derived (bytes(skey) returns the
            seed); the private nonce of the participant (r); the keyset encoding
            of the participants (L); the aggregate public key (X); the aggregate
            public nonce point (R); and the message (M).
        """
        ...

    @abstractmethod
    def public(self) -> AbstractPartialSignature:
        """Return a copy of the instance with only the public value (s_i)."""
        ...

    @property
    @abstractmethod
    def c_i(self) -> bytes:
        """The non-interactive challenge for the participant."""
        ...

    @property
    @abstractmethod
    def s_i(self) -> bytes:
        """The partial signature scalar."""
        ...

    @property
    @abstractmethod
    def R(self) -> bytes:
        """The aggregate nonce point."""
        ...

    @property
    @abstractmethod
    def M(self) -> bytes:
        """The message to be signed."""
        ...


class AbstractPublicKey(ExtendedDict):
    @classmethod
    @abstractmethod
    def create(cls, keys: list) -> AbstractPublicKey:
        """Create a new instance from a list/tuple of participant VerifyKeys.
            This must derive the keyset encoding (L) and the aggregate key
            (denoted X in the MuSig paper and gvkey in this class).
        """
        ...

    @abstractmethod
    def public(self) -> AbstractPublicKey:
        """Return a copy of the instance with only the public value (gvkey)."""
        ...

    @abstractmethod
    def verify(self, sig: AbstractSignature) -> bool:
        """Check if a given signature is valid for the current aggregate key."""
        ...

    @classmethod
    @abstractmethod
    def aggregate_public_keys(cls, vkeys: list[VerifyKey|bytes], key_set_L: bytes = None) -> bytes:
        """Calculate the aggregate public key from the participant keys."""
        ...

    @classmethod
    @abstractmethod
    def pre_agg_key_transform(cls, vkey: VerifyKey, key_set_L: bytes) -> bytes:
        """Transform a participant VerifyKey prior to calculating the aggregate
            public key. This is called by aggregate_public_keys on every
            participant VerifyKey.
        """
        ...

    @classmethod
    @abstractmethod
    def encode_key_set(cls, vkeys: list) -> bytes:
        """Sort the participant keys into a deterministic order, then hash the
            list to produce the keyset encoding (L).
        """
        ...

    @property
    @abstractmethod
    def L(self) -> bytes:
        """The keyset encoding used for calculating partial signatures."""
        ...

    @property
    @abstractmethod
    def gvkey(self) -> bytes:
        """The bytes of the aggregate key (denoted X in the MuSig paper)."""
        ...

    @property
    @abstractmethod
    def vkeys(self) -> tuple[VerifyKey, ...]:
        """Tuple of untransformed participant VerifyKeys."""
        ...


class AbstractSignature(ExtendedDict):
    @classmethod
    @abstractmethod
    def create(cls, R: bytes, M: bytes, parts: list[AbstractPartialSignature]) -> AbstractSignature:
        """Create a new instance using the aggregate nonce point (R), the
            message (M), and the list/tuple of partial signatures (scalars s_i).
        """
        ...

    @property
    @abstractmethod
    def R(self) -> bytes:
        """Aggregate nonce point."""
        ...

    @property
    @abstractmethod
    def s(self) -> bytes:
        """Aggregate signature made from summing partial signatures."""
        ...

    @property
    @abstractmethod
    def M(self) -> bytes:
        """Message to be signed."""
        ...

    @property
    @abstractmethod
    def parts(self) -> tuple[AbstractPartialSignature, ...]:
        """Tuple of partial signatures summed together to create the signature."""
        ...


class AbstractSingleSigKey(ExtendedDict):
    @abstractmethod
    def sign_message(self, M: bytes) -> AbstractSignature:
        """Sign a message (M) and return a signature."""
        ...

    @property
    @abstractmethod
    def skey(self) -> SigningKey|None:
        """The SigningKey used for creating signatures."""
        ...

    @property
    @abstractmethod
    def vkey(self) -> AbstractPublicKey|None:
        """The aggregate public key for verifying signatures."""
        ...

    @property
    @abstractmethod
    def vkey_base(self) -> VerifyKey|None:
        """The VerifyKey base used to calculate the aggregate public key."""
        ...


class AbstractProtocolState(EnumMeta):
    """Enum mapping human-readable protocol states to 1-byte ints."""
    ...


class AbstractProtocolMessage(ExtendedDict):
    @abstractmethod
    def parse_message(self) -> None:
        """Parses the message into parts based upon protocol state, e.g. lists
            of participant keys, nonces, nonce commitments, etc, storing the
            result in self.message_parts/self['message_parts'].
        """
        ...

    @abstractmethod
    def add_signature(self, skey: SigningKey) -> AbstractProtocolMessage:
        """Add a signature to the message using the provided SigningKey. This
            signs the protocol state + message, attaching the signature and the
            relevant VerifyKey to the instance.
        """
        ...

    @abstractmethod
    def check_signature(self) -> bool:
        """Return true if and only if the instance contains a VerifyKey and a
            signature valid for the protocol state + message, else return False.
        """
        ...

    @classmethod
    @abstractmethod
    def create(cls, id: UUID|None, state: AbstractProtocolState, data: list) -> AbstractProtocolMessage:
        """Create a new instance with the given id, state, and data.
            NB: id=None should be accepted only for state=EMPTY.
        """
        ...

    @property
    @abstractmethod
    def session_id(self) -> UUID:
        """The UUID of the signing session for which this message was constructed."""
        ...

    @property
    @abstractmethod
    def state(self) -> AbstractProtocolState:
        """The protocol state of the message."""
        ...

    @property
    @abstractmethod
    def message(self) -> bytes:
        """The message itself."""
        ...

    @property
    @abstractmethod
    def message_parts(self) -> list:
        """The things that serialize into and deserialize from self.message."""
        ...

    @property
    @abstractmethod
    def signature(self) -> AbstractSignature:
        """The Signature result of add_signature."""
        ...

    @property
    @abstractmethod
    def vkey(self) -> AbstractPublicKey:
        """The VerifyKey used to verify the signature."""
        ...


class AbstractSigningSession(ExtendedDict):
    @abstractmethod
    def add_participant_keys(self, keys: VerifyKey|list[VerifyKey]) -> None:
        """Add participant VerifyKey(s)."""
        ...

    @abstractmethod
    def add_nonce_commitment(self, commitment: AbstractNonceCommitment, vkey: VerifyKey) -> None:
        """Add a NonceCommitment from a participant identified by the VerifyKey."""
        ...

    @abstractmethod
    def add_nonce(self, nonce: AbstractNonce, vkey: VerifyKey) -> None:
        """Add a Nonce from a participant identified by the VerifyKey."""
        ...

    @abstractmethod
    def make_partial_signature(self) -> AbstractPartialSignature:
        """Create a partial signature to be broadcast to other participants."""
        ...

    @abstractmethod
    def add_partial_signature(self, sig: AbstractPartialSignature, vkey: VerifyKey) -> None:
        """Add a PartialSignature from a participant identified by the VerifyKey."""
        ...

    @abstractmethod
    def update_protocol_state(self) -> None:
        """Handle transitions between ProtocolStates as the SigningSession values
            are updated.
        """
        ...

    @property
    @abstractmethod
    def id(self) -> UUID:
        """The UUID of the session."""
        ...

    @property
    @abstractmethod
    def number_of_participants(self) -> int:
        """The number of participants expected to participate in the protocol."""
        ...

    @property
    @abstractmethod
    def protocol_state(self) -> AbstractProtocolState:
        """The current state of the session."""
        ...

    @property
    @abstractmethod
    def last_updated(self) -> int:
        """A timestamp recording the last time the protocol state was updated."""
        ...

    @property
    @abstractmethod
    def skey(self) -> SigningKey:
        """The SigningKey of the participant using this instance."""
        ...

    @property
    @abstractmethod
    def vkeys(self) -> tuple[VerifyKey, ...]:
        """A tuple of participant VerifyKeys."""
        ...

    @property
    @abstractmethod
    def nonce_commitments(self) -> dict[VerifyKey, AbstractNonceCommitment]:
        """A dict mapping participant VerifyKey to NonceCommitment."""
        ...

    @property
    @abstractmethod
    def nonce_points(self) -> dict[VerifyKey, AbstractNonce]:
        """A dict mapping participant VerifyKey to Nonce. Note that the Nonce
            for the participant using this instance will include the private
            scalar value, but the Nonces of other participants will include only
            the public point values.
        """
        ...

    @property
    @abstractmethod
    def aggregate_nonce(self) -> AbstractNonce:
        """The aggregate nonce point for the session."""
        ...

    @property
    @abstractmethod
    def message(self) -> bytes:
        """The message to be n-of-n signed."""
        ...

    @property
    @abstractmethod
    def partial_signatures(self) -> dict[VerifyKey, AbstractPartialSignature]:
        """A dict mapping participant VerifyKey to PartialSignature (public
            values s_i only).
        """
        ...

    @property
    @abstractmethod
    def public_key(self) -> AbstractPublicKey:
        """The aggregate public key for the session."""
        ...

    @property
    @abstractmethod
    def signature(self) -> AbstractSignature:
        """The final n-of-n signature."""
        ...
