from __future__ import annotations
from abc import abstractclassmethod, abstractmethod, abstractproperty
from enum import EnumMeta
from uuid import UUID
from nacl.signing import SigningKey, VerifyKey


class AbstractNonce(dict):
    @abstractmethod
    def __setitem__(self, key, value) -> None:
        ...

    @abstractmethod
    def __bytes__(self) -> bytes:
        ...

    @abstractmethod
    def __str__(self) -> str:
        ...

    @abstractmethod
    def __hash__(self) -> int:
        ...

    @abstractmethod
    def __eq__(self) -> bool:
        ...

    @abstractmethod
    def copy(self) -> AbstractNonce:
        ...

    @abstractmethod
    def public(self) -> AbstractNonce:
        ...

    @abstractclassmethod
    def from_bytes(cls, data: bytes) -> AbstractNonce:
        ...

    @abstractclassmethod
    def from_str(cls, data: str) -> AbstractNonce:
        ...

    @abstractproperty
    def r(self):
        ...

    @abstractproperty
    def R(self):
        ...


class AbstractNonceCommitment(dict):
    @abstractmethod
    def __setitem__(self, key, value) -> None:
        ...

    @abstractmethod
    def __bytes__(self) -> bytes:
        ...

    @abstractmethod
    def __str__(self) -> str:
        ...

    @abstractmethod
    def __hash__(self) -> int:
        ...

    @abstractmethod
    def __eq__(self) -> bool:
        ...

    @abstractmethod
    def copy(self) -> AbstractNonceCommitment:
        ...

    @abstractmethod
    def is_valid_for(self, nonce: AbstractNonce) -> bool:
        ...

    @abstractmethod
    def serialize(self) -> str:
        ...

    @abstractclassmethod
    def deserialize(cls, data) -> AbstractNonceCommitment:
        ...

    @abstractproperty
    def HR(self):
        ...


class AbstractPartialSignature(dict):
    @abstractmethod
    def __setitem__(self, key, value) -> None:
        ...

    @abstractmethod
    def __bytes__(self) -> bytes:
        ...

    @abstractmethod
    def __str__(self) -> str:
        ...

    @abstractmethod
    def __hash__(self) -> int:
        ...

    @abstractmethod
    def __eq__(self) -> bool:
        ...

    @abstractclassmethod
    def from_bytes(cls, data: bytes) -> AbstractPartialSignature:
        ...

    @abstractclassmethod
    def from_str(cls, data: str) -> AbstractPartialSignature:
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


class AbstractPublicKey(dict):
    @abstractmethod
    def __setitem__(self, key, value) -> None:
        ...

    @abstractmethod
    def __bytes__(self) -> bytes:
        ...

    @abstractmethod
    def __str__(self) -> str:
        ...

    @abstractmethod
    def __hash__(self) -> int:
        ...

    @abstractmethod
    def __eq__(self) -> bool:
        ...

    @abstractclassmethod
    def from_bytes(cls, data: bytes) -> AbstractPublicKey:
        ...

    @abstractclassmethod
    def from_str(cls, data: str) -> AbstractPublicKey:
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


class AbstractSignature(dict):
    @abstractmethod
    def __setitem__(self, key, value) -> None:
        ...

    @abstractmethod
    def __bytes__(self) -> bytes:
        ...

    @abstractmethod
    def __str__(self) -> str:
        ...

    @abstractmethod
    def __hash__(self) -> int:
        ...

    @abstractmethod
    def __eq__(self) -> bool:
        ...

    @abstractclassmethod
    def from_bytes(cls, data: bytes) -> AbstractSignature:
        ...

    @abstractclassmethod
    def from_str(cls, data: str) -> AbstractSignature:
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


class AbstractSingleSigKey(dict):
    @abstractmethod
    def __setitem__(self, key, value) -> None:
        ...

    @abstractmethod
    def __bytes__(self) -> bytes:
        ...

    @abstractmethod
    def __str__(self) -> str:
        ...

    @abstractmethod
    def __hash__(self) -> int:
        ...

    @abstractmethod
    def __eq__(self) -> bool:
        ...

    @abstractclassmethod
    def from_bytes(cls, data: bytes) -> AbstractSingleSigKey:
        ...

    @abstractclassmethod
    def from_str(cls, data: str) -> AbstractSingleSigKey:
        ...

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


class AbstractProtocolMessage(dict):
    @abstractmethod
    def __setitem__(self, key, value) -> None:
        ...

    @abstractmethod
    def __bytes__(self) -> bytes:
        ...

    @abstractmethod
    def __str__(self) -> str:
        ...

    @abstractmethod
    def __hash__(self) -> int:
        ...

    @abstractmethod
    def __eq__(self) -> bool:
        ...

    @abstractclassmethod
    def from_bytes(cls, data: bytes) -> AbstractProtocolMessage:
        ...

    @abstractclassmethod
    def from_str(cls, data: str) -> AbstractProtocolMessage:
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
    def signature(self):
        ...

    @abstractproperty
    def vkey(self):
        ...
