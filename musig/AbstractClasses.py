from __future__ import annotations
from abc import ABC, abstractclassmethod, abstractmethod, abstractproperty
from enum import EnumMeta
from uuid import UUID
from nacl.signing import SigningKey, VerifyKey


class AbstractNonce(ABC):
    @abstractmethod
    def copy(self) -> AbstractNonce:
        ...

    @abstractmethod
    def public(self) -> AbstractNonce:
        ...

    @abstractmethod
    def serialize(self) -> str:
        ...

    @abstractproperty
    def r(self):
        ...

    @abstractproperty
    def R(self):
        ...


class AbstractNonceCommitment(ABC):
    @abstractmethod
    def copy(self) -> AbstractNonceCommitment:
        ...

    @abstractmethod
    def is_valid_for(self, nonce: AbstractNonce) -> bool:
        ...

    @abstractmethod
    def serialize(self) -> str:
        ...

    @abstractproperty
    def HR(self):
        ...


class AbstractPartialSignature(ABC):
    @abstractmethod
    def serialize(self) -> str:
        ...

    @abstractclassmethod
    def deserialize(cls, data) -> AbstractPartialSignature:
        ...

    @abstractclassmethod
    def create(cls, skey: SigningKey, r: bytes, L: bytes, X: AbstractPublicKey,
            R: bytes, M: bytes) -> dict:
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


class AbstractPublicKey(ABC):
    @abstractmethod
    def serialize(self) -> str:
        ...

    @abstractclassmethod
    def deserialize(cls, data) -> AbstractPublicKey:
        ...

    @abstractmethod
    def verify(self, sig: AbstractSignature) -> bool:
        ...

    @abstractclassmethod
    def aggregate_public_key(cls, vkeys: list, key_set_L=None) -> bytes:
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


class AbstractSignature(ABC):
    @abstractmethod
    def serialize(self) -> str:
        ...

    @abstractclassmethod
    def deserialize(cls, data) -> AbstractSignature:
        ...

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


class AbstractSingleSigKey(ABC):
    @abstractmethod
    def serialize(self) -> str:
        ...

    @abstractclassmethod
    def deserialize(cls, data) -> AbstractSingleSigKey:
        ...

    @abstractmethod
    def sign_message(self, M: bytes) -> AbstractSignature:
        ...


class AbstractProtocolState(EnumMeta):
        ...


class AbstractProtocolMessage(ABC):
    @abstractmethod
    def __bytes__(self) -> bytes:
        ...

    @abstractmethod
    def __eq__(self, other) -> bool:
        ...

    @abstractclassmethod
    def from_bytes(cls, data: bytes) -> AbstractProtocolMessage:
        ...

    @abstractmethod
    def __str__(self) -> str:
        ...

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
    def from_str(cls, data: str) -> AbstractProtocolMessage:
        ...

    @abstractclassmethod
    def create(cls, id: UUID, state: AbstractProtocolState, data: list) -> AbstractProtocolMessage:
        ...
