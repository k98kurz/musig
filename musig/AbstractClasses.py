from __future__ import annotations
from abc import abstractclassmethod, abstractmethod, abstractproperty
from base64 import b64encode
from enum import EnumMeta
from musig import bytes_are_same
from nacl.signing import SigningKey, VerifyKey
from uuid import UUID


class ExtendedDict(dict):
    """ExtendedDict handles some serialization/deserialization."""
    def __setitem__(self, key, value) -> None:
        if hasattr(self, key):
            setattr(self, f'_{key}', value)
            if type(value) in (int, str):
                super().__setitem__(key, value)
            elif type(value) is bytes:
                super().__setitem__(key, b64encode(value).decode())
            elif type(value) in (tuple, list):
                super().__setitem__(key, tuple([b64encode(bytes(k)).decode() for k in value]))
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
        ...

    def __str__(self) -> str:
        return bytes(self).hex()

    def __hash__(self) -> int:
        return hash(bytes(self))

    def __eq__(self, other) -> bool:
        """Timing-attack safe comparison."""
        if not isinstance(other, self.__class__):
            return False
        return bytes_are_same(bytes(self), bytes(other))

    @abstractclassmethod
    def from_bytes(cls, data: bytes) -> ExtendedDict:
        ...

    @classmethod
    def from_str(cls, data: str) -> ExtendedDict:
        return cls.from_bytes(bytes.fromhex(data))


class AbstractNonce(ExtendedDict):
    @abstractmethod
    def __add__(self, other: AbstractNonce) -> AbstractNonce:
        ...

    @abstractmethod
    def copy(self) -> AbstractNonce:
        ...

    @abstractmethod
    def public(self) -> AbstractNonce:
        ...

    @abstractproperty
    def r(self):
        ...

    @abstractproperty
    def R(self):
        ...


class AbstractNonceCommitment(ExtendedDict):
    @abstractclassmethod
    def create(cls, nonce: AbstractNonce) -> AbstractNonceCommitment:
        ...

    @abstractmethod
    def copy(self) -> AbstractNonceCommitment:
        ...

    @abstractmethod
    def is_valid_for(self, nonce: AbstractNonce) -> bool:
        ...

    @abstractproperty
    def HR(self):
        ...


class AbstractPartialSignature(ExtendedDict):
    @abstractclassmethod
    def create(cls, skey: SigningKey, r: bytes, L: bytes, X: AbstractPublicKey,
            R: bytes, M: bytes) -> dict:
        ...

    @abstractmethod
    def public(self) -> AbstractPartialSignature:
        ...

    @abstractproperty
    def c_i(self):
        ...

    @abstractproperty
    def s_i(self):
        ...

    @abstractproperty
    def R(self):
        ...

    @abstractproperty
    def M(self):
        ...


class AbstractPublicKey(ExtendedDict):
    @abstractclassmethod
    def create(cls, keys: list) -> AbstractPublicKey:
        ...

    @abstractmethod
    def public(self) -> AbstractPublicKey:
        ...

    @abstractmethod
    def verify(self, sig: AbstractSignature) -> bool:
        ...

    @abstractclassmethod
    def aggregate_public_keys(cls, vkeys: list, key_set_L=None) -> bytes:
        ...

    @abstractclassmethod
    def pre_agg_key_transform(cls, vkey: VerifyKey, key_set_L: bytes) -> bytes:
        ...

    @abstractclassmethod
    def encode_key_set(cls, vkeys: list) -> bytes:
        ...

    @abstractproperty
    def L(self):
        ...

    @abstractproperty
    def gvkey(self):
        ...

    @abstractproperty
    def vkeys(self):
        ...


class AbstractSignature(ExtendedDict):
    @abstractclassmethod
    def create(cls, R: bytes, M: bytes, parts: list) -> dict:
        ...

    @abstractproperty
    def R(self):
        ...

    @abstractproperty
    def s(self):
        ...

    @abstractproperty
    def M(self):
        ...

    @abstractproperty
    def parts(self):
        ...


class AbstractSingleSigKey(ExtendedDict):
    @abstractmethod
    def sign_message(self, M: bytes) -> AbstractSignature:
        ...

    @abstractproperty
    def skey(self):
        ...

    @abstractproperty
    def vkey(self):
        ...

    @abstractproperty
    def vkey_base(self):
        ...


class AbstractProtocolState(EnumMeta):
    ...


class AbstractProtocolMessage(ExtendedDict):
    @abstractmethod
    def parse_message(self) -> None:
        ...

    @abstractmethod
    def add_signature(self, skey: SigningKey) -> AbstractProtocolMessage:
        ...

    @abstractmethod
    def check_signature(self) -> bool:
        ...

    @abstractclassmethod
    def create(cls, id: UUID, state: AbstractProtocolState, data: list) -> AbstractProtocolMessage:
        ...

    @abstractproperty
    def session_id(self):
        ...

    @abstractproperty
    def state(self):
        ...

    @abstractproperty
    def message(self):
        ...

    @abstractproperty
    def message_parts(self):
        ...

    @abstractproperty
    def signature(self):
        ...

    @abstractproperty
    def vkey(self):
        ...


class AbstractSigningSession(ExtendedDict):
    @abstractmethod
    def add_participant_keys(self, keys) -> None:
        ...

    @abstractmethod
    def add_nonce_commitment(self, commitment: AbstractNonceCommitment, vkey: VerifyKey) -> None:
        ...

    @abstractmethod
    def add_nonce(self, nonce: AbstractNonce, vkey: VerifyKey) -> None:
        ...

    @abstractmethod
    def make_partial_signature(self) -> AbstractPartialSignature:
        ...

    @abstractmethod
    def add_partial_signature(self, sig: AbstractPartialSignature, vkey: VerifyKey) -> None:
        ...

    @abstractmethod
    def update_protocol_state(self) -> None:
        ...

    @abstractproperty
    def id(self):
        ...

    @abstractproperty
    def number_of_participants(self):
        ...

    @abstractproperty
    def protocol_state(self):
        ...

    @abstractproperty
    def last_updated(self):
        ...

    @abstractproperty
    def skey(self):
        ...

    @abstractproperty
    def vkeys(self):
        ...

    @abstractproperty
    def nonce_commitments(self):
        ...

    @abstractproperty
    def nonce_points(self):
        ...

    @abstractproperty
    def aggregate_nonce(self):
        ...

    @abstractproperty
    def message(self):
        ...

    @abstractproperty
    def partial_signatures(self):
        ...

    @abstractproperty
    def public_key(self):
        ...

    @abstractproperty
    def signature(self):
        ...
