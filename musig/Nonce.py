from __future__ import annotations
from base64 import b64encode, b64decode
from json import loads
from musig.abstractclasses import AbstractNonce
from musig.helpers import aggregate_points, bytes_are_same, clamp_scalar
from secrets import token_bytes
import nacl.bindings


class Nonce(dict, AbstractNonce):
    """A class that handles generating, serializing, and deserializing nonces."""

    def __init__(self, data=None) -> None:
        """Initialize the instance, either with supplied data or with new values.
            Call with `data=None` to create a new Nonce.
            Call with `data=(r, R)` or `data=[r, R]` to restore a full Nonce.
            Call with `data=R` to restore just the nonce point.
            (Each of `r` and `R` must be type bytes.)
            Anything else will be sent to Nonce.deserialize() to be parsed.
        """
        if data is None:
            # create new nonce
            self._r = clamp_scalar(token_bytes(nacl.bindings.crypto_scalarmult_ed25519_SCALARBYTES))
            self._R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(self._r)
            super().__init__({
                'r': b64encode(self._r).decode(),
                'R': b64encode(self._R).decode()
            })
        elif type(data) in [list, tuple] and len(data) == 2:
            # restore a full Nonce given the two values
            (r, R) = data
            self._r = r if type(r) is bytes else b64decode(r)
            self._R = R if type(R) is bytes else b64decode(R)
            super().__init__({
                'r': b64encode(self._r).decode(),
                'R': b64encode(self._R).decode()
            })
        elif type(data) is bytes:
            # restore a Nonce point (public value)
            self._R = data
            super().__init__({'R': b64encode(self._R).decode()})
        else:
            # attempt to deserialize the input
            data = self.deserialize(data)
            for field in data:
                val = data[field] if type(data[field]) is bytes else b64decode(data[field])
                setattr(self, f'_{field}', val)
                self[field] = b64encode(val).decode()

    def __repr__(self) -> str:
        """Result of calling repr() on an instance."""
        if self.r != None:
            return '64r.' + b64encode(self.r).decode()
        if self.R != None:
            return '64R.' + b64encode(self._R).decode()
        return ''

    def __str__(self) -> str:
        """Result of calling str() on an instance."""
        if self.r != None:
            return '16r.' + self.r.hex()
        if self.R != None:
            return '16R.' + self.R.hex()
        return ''

    def __bytes__(self):
        """Result of calling bytes() on an instance."""
        if self.R is not None:
            return self.R
        return b''

    def __add__(self, other: Nonce) -> Nonce:
        """Result of the + operation between two Nonces."""
        R_sum = aggregate_points([self.R, other.R])
        return Nonce(R_sum)

    def __hash__(self) -> int:
        """Make class hashable for inclusion in sets."""
        return hash(self._R)

    def __eq__(self, other) -> bool:
        """Enforce timing-attack safe comparison."""
        if not isinstance(other, self.__class__):
            return False
        return bytes_are_same(bytes(self), bytes(other))

    def copy(self) -> Nonce:
        """Make a copy without serializing and deserializing."""
        return Nonce({**self})

    def public(self) -> Nonce:
        """Return a Nonce with only the public nonce point."""
        return Nonce(self.R)

    def serialize(self) -> str:
        """Return a serialized representation of the instance."""
        return repr(self)

    @classmethod
    def deserialize(cls, data):
        """Deserialize some `data` into an instance.
            Acceptable types are `dict` and `str`.
            Acceptable format for `dict` is {'r': bytes, 'R': bytes}.
            Acceptable formats for `str` are '16r.{hexadecimal}',
            '16R.{hexadecimal}', '64r.{base64}', '64R.{base64}', and
            'json.{json_string}'.
        """
        if isinstance(data, dict) and len(data.keys()) > 0:
            # deserialize json.loads() output
            if 'r' in data:
                r = b64decode(data['r'])
            if 'R' in data:
                R = b64decode(data['R'])

            return Nonce((r, R)) if 'r' in dir() else Nonce(R)
        elif type(data) is str:
            # split the data and parse appropriately
            parts = data.split('.')
            if len(parts) < 2:
                raise ValueError('input str must have at least 2 parts delimited by .')
            elif parts[0] == '64R':
                # parse base64 public nonce point
                R = b64decode(parts[1])
            elif parts[0] == '64r':
                # parse the b64 encoded private nonce and load or derive R
                r = b64decode(parts[1])
                if len(parts) == 3:
                    R = b64decode(parts[2])
                else:
                    R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r)
            elif parts[0] == '16R':
                # parse the hex public nonce point
                R = bytes.fromhex(parts[1])
            elif parts[0] == '16r':
                # parse the hex encoded private nonce and load or derive R
                r = bytes.fromhex(parts[1])
                if len(parts) == 3:
                    R = bytes.fromhex(parts[2])
                else:
                    R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r)
            elif parts[0] == 'json':
                # load the json and instantiate
                data = loads('.'.join(parts[1:]))
                if 'r' in data:
                    r = b64decode(data['r'])
                if 'R' in data:
                    R = b64decode(data['R'])
            else:
                raise ValueError('unknown/invalid serialization')

            return Nonce((r, R)) if 'r' in dir() else Nonce(R)

    # add readonly properties
    r = property(lambda self: self._r if hasattr(self, '_r') else None)
    R = property(lambda self: self._R if hasattr(self, '_R') else None)
