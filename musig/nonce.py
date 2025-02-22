from __future__ import annotations
from base64 import b64encode, b64decode
from musig.abstractclasses import AbstractNonce
from musig.helpers import aggregate_points, clamp_scalar
from secrets import token_bytes
import nacl.bindings


class Nonce(AbstractNonce):
    """A class that handles generating, serializing, and deserializing nonces."""

    def __init__(self, data: dict = None) -> None:
        """Initialize the instance, either with supplied data or with new values.
            Call with `data=None` to create a new Nonce.
            Call with `data={r:b64val}` or `{r:b64val, R:b64val}` to restore a full Nonce.
            Call with `data={R:b64val}` to restore a public Nonce.
        """
        if not isinstance(data, dict) and data is not None:
            raise TypeError('Nonce can be instantiated only with None or dict.')

        if data is None:
            # create new nonce
            self.r = clamp_scalar(token_bytes(nacl.bindings.crypto_scalarmult_ed25519_SCALARBYTES))
            self.R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(self.r)
        else:
            # restore a Nonce from dict (e.g. json.loads result)
            if 'R' in data:
                R = data['R']
                self.R = R if type(R) is bytes else b64decode(R)
            if 'r' in data:
                r = data['r']
                self.r = r if type(r) is bytes else b64decode(r)
                self.R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(self.r)

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on an instance."""
        if self.r is not None:
            return b'r' + self.r
        if self.R is not None:
            return self.R
        return b''

    @classmethod
    def from_bytes(cls, data: bytes) -> Nonce:
        """Deserializes output from __bytes__."""
        if type(data) is not bytes:
            raise TypeError('cannot call from_bytes with non-bytes param')
        if len(data) not in (32, 33):
            raise ValueError('byte length must be 32 or 33')

        if len(data) == 33:
            # restore full Nonce with private scalar and public point.
            r = data[1:]
            R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r)
            return cls({
                'r': r,
                'R': R
            })
        else:
            # restore partial Nonce with just the public point.
            return cls({'R': data})

    def __add__(self, other: Nonce) -> Nonce:
        """Result of the + operation between two Nonces."""
        R_sum = aggregate_points([self.R, other.R])
        return Nonce.from_bytes(R_sum)

    def copy(self) -> Nonce:
        """Make a copy without serializing and deserializing."""
        return Nonce({**self})

    def public(self) -> Nonce:
        """Return a Nonce with only the public nonce point."""
        return self.__class__({'R': b64encode(self.R).decode()})

    # properties
    @property
    def r(self) -> bytes|None:
        """The private scalar value."""
        return self._r if hasattr(self, '_r') else None

    @r.setter
    def r(self, value: bytes):
        """The private scalar value."""
        if not isinstance(value, bytes):
            raise TypeError('r value must be bytes')
        if len(value) != 32:
            raise ValueError('r value must have length 32')

        self['r'] = value

    @property
    def R(self) -> bytes|None:
        """The public point value."""
        return self._R if hasattr(self, '_R') else None

    @R.setter
    def R(self, value: bytes):
        """The public point value."""
        if not isinstance(value, bytes):
            raise TypeError('R value must be bytes')
        if len(value) != 32:
            raise ValueError('R value must have length 32')

        self['R'] = value
