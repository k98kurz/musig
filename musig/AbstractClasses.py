from __future__ import annotations
from abc import ABC, abstractclassmethod, abstractmethod, abstractproperty
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
