from __future__ import annotations
from base64 import b64decode
from musig.abstractclasses import AbstractPublicKey, AbstractPartialSignature
from musig.helpers import derive_key_from_seed, derive_challenge
from nacl.signing import SigningKey
import nacl.bindings


class PartialSignature(AbstractPartialSignature):
    """A class that handles creation, serialization, and deserialization of
        partial signatures used to create MuSig aggregate signatures.
    """
    def __init__(self, data: dict) -> None:
        """Initialize an instance with dict.
            At a minimum data should include s_i key with base64-encoded value
            of 32 bytes; keys of c_i and R with base64-encoded value of 32 bytes
            each are optional; key of M with base64-encoded value of bytes is
            also optional.
        """
        if not isinstance(data, dict):
            raise TypeError('data must be type dict')

        if 'c_i' in data:
            self.c_i = data['c_i'] if type(data['c_i']) is bytes else b64decode(data['c_i'])
        if 's_i' in data:
            self.s_i = data['s_i'] if type(data['s_i']) is bytes else b64decode(data['s_i'])
        if 'R' in data:
            self.R = data['R'] if type(data['R']) is bytes else b64decode(data['R'])
        if 'M' in data:
            self.M = data['M'] if type(data['M']) is bytes else b64decode(data['M'])

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on an instance."""
        if self.c_i is not None and self.R is not None and self.M is not None:
            return self.s_i + self.c_i + self.R + self.M
        return self.s_i

    @classmethod
    def from_bytes(cls, data: bytes) -> PartialSignature:
        """Deserializes output from __bytes__."""
        if type(data) is not bytes:
            raise TypeError('data must be bytes of len == 32 or >=96')

        if len(data) < 32 or (len(data) > 32 and len(data) < 96):
            raise ValueError('data must be bytes of len == 32 or >=96')

        new_data = {
            's_i': data[:32]
        }

        if len(data) >= 96:
            new_data['c_i'] = data[32:64]
            new_data['R'] = data[64:96]

        if len(data) > 96:
            new_data['M'] = data[96:]

        return cls(new_data)

    @classmethod
    def create(cls, skey: SigningKey, r_i: bytes, L: bytes, X: AbstractPublicKey,
            R: bytes, M: bytes) -> dict:
        """Create a new instance using the SigningKey of the participant (skey),
            from which the private key will be derived (bytes(skey) returns the
            seed); the private nonce of the participant (r_i); the keyset encoding
            of the participants (L); the aggregate public key (X); the aggregate
            public nonce point (R); and the message (M).
        """
        x_i = derive_key_from_seed(bytes(skey))
        c_i = derive_challenge(L, bytes(skey.verify_key), bytes(X.public()), R, M)
        s_i = nacl.bindings.crypto_core_ed25519_scalar_mul(c_i, x_i)
        s_i = nacl.bindings.crypto_core_ed25519_scalar_add(r_i, s_i)

        return cls({
            'c_i': c_i,
            's_i': s_i,
            'R': R,
            'M': M,
        })

    def public(self) -> PartialSignature:
        """Return a copy of the instance with only the public value (s_i)."""
        return self.__class__({'s_i': self.s_i})

    @property
    def c_i(self) -> bytes|None:
        """The non-interactive challenge for the participant."""
        return self._c_i if hasattr(self, '_c_i') else None

    @c_i.setter
    def c_i(self, data: bytes):
        """The non-interactive challenge for the participant."""
        if type(data) is not bytes:
            raise TypeError('data must be bytes of len 32')
        if len(data) != 32:
            raise ValueError('data must be bytes of len 32')

        self['c_i'] = data

    @property
    def s_i(self) -> bytes|None:
        """The partial signature scalar."""
        return self._s_i if hasattr(self, '_s_i') else None

    @s_i.setter
    def s_i(self, data: bytes):
        """The partial signature scalar."""
        if type(data) is not bytes:
            raise TypeError('data must be bytes of len 32')
        if len(data) != 32:
            raise ValueError('data must be bytes of len 32')

        self['s_i'] = data

    @property
    def R(self) -> bytes|None:
        """The aggregate nonce point."""
        return self._R if hasattr(self, '_R') else None

    @R.setter
    def R(self, data: bytes):
        """The aggregate nonce point."""
        if type(data) is not bytes:
            raise TypeError('data must be bytes of len 32')
        if len(data) != 32:
            raise ValueError('data must be bytes of len 32')

        self['R'] = data

    @property
    def M(self) -> bytes|None:
        """The message to be signed."""
        return self._M if hasattr(self, '_M') else None

    @M.setter
    def M(self, data: bytes):
        """The message to be signed."""
        if type(data) is not bytes:
            raise TypeError('data must be bytes')

        self['M'] = data
