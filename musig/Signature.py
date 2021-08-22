from __future__ import annotations
from base64 import b64encode, b64decode
from json import loads
from musig.helpers import bytes_are_same
from musig.abstractclasses import AbstractSignature, AbstractPartialSignature
from musig.partialsignature import PartialSignature
import nacl.bindings


class Signature(dict, AbstractSignature):
    """A class that sums PartialSignatures into a full Signature."""
    def __init__(self, data=None) -> None:
        """Initialize an instance with params for the `create` method or
            deserialize.
            Call with `data=()` to create a new __class__.
            Call with `data=str` or `data=bytes` to implicitly call `deserialize`.
            Call with `data=dict` to instantiate with key:value definition, where
            each value is b64 encoded.
        """
        if type(data) in (list, tuple) and len(data) == 3:
            data = self.create(*data)

        if type(data) in (str, bytes):
            data = self.deserialize(data)

        if isinstance(data, dict):
            # restore from json loads result
            super().__init__(data)
            if 'R' in data:
                self._R = b64decode(data['R'])
            if 'M' in data:
                self._M = b64decode(data['M'])
            if 's' in data:
                self._s = b64decode(data['s'])
            if 'parts' in data:
                self._parts = [PartialSignature(b64decode(p)) for p in data['parts']]
        else:
            raise ValueError('instantiation requires a list of values or deserialized dict')

    def __str__(self) -> str:
        """Result of calling str() on an instance."""
        parts = [
            self.R.hex(),
            self.s.hex(),
            self.M.hex(),
            ':'.join([bytes(p).hex() for p in self.parts]),
        ]
        return '16.' + '.'.join(parts)

    def __repr__(self) -> str:
        """Result of calling repr() on an instance."""
        parts = [
            b64encode(self.R).decode(),
            b64encode(self.s).decode(),
            b64encode(self.M).decode(),
            ':'.join([b64encode(bytes(p)).decode() for p in self.parts]),
        ]
        return '64.' + '.'.join(parts)

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on an instance."""
        return self.R + self.s + self.M

    def __hash__(self) -> int:
        """Make class hashable for inclusion in sets."""
        return hash(bytes(self))

    def __eq__(self, other) -> bool:
        """Enforce timing-attack safe comparison."""
        if not isinstance(other, self.__class__):
            return False
        return bytes_are_same(bytes(self), bytes(other))

    def serialize(self) -> str:
        """Return a serialized representation of the instance."""
        return repr(self)

    @classmethod
    def deserialize(cls, data) -> Signature:
        if isinstance(data, bytes):
            if len(data) < 32*2+1:
                raise ValueError('input bytes must have len >= 65')
            R = data[:32]
            s = data[32:64]
            M = data[64:]
            return cls({
                'R': b64encode(R).decode(),
                's': b64encode(s).decode(),
                'M': b64encode(M).decode(),
            })
        elif isinstance(data, str):
            # split the parts
            parts = data.split('.')
            if parts[0] != 'json' and len(parts) != 5:
                raise ValueError('input str must have 5 parts delimited by .')

            if parts[0] == '16':
                R = bytes.fromhex(parts[1])
                s = bytes.fromhex(parts[2])
                M = bytes.fromhex(parts[3])
                parts = [bytes.fromhex(p) for p in parts[4].split(':')]
            elif parts[0] == '64':
                R = b64decode(parts[1])
                s = b64decode(parts[2])
                M = b64decode(parts[3])
                parts = [b64decode(p) for p in parts[4].split(':')]
            elif parts[0] == 'json':
                return cls(loads('.'.join(parts[1:])))

            return cls({
                'R': b64encode(R).decode(),
                's': b64encode(s).decode(),
                'M': b64encode(M).decode(),
                'parts': [b64encode(p).decode() for p in parts],
            })
        else:
            raise ValueError('unknown/invalid serialization')

    @classmethod
    def create(cls, R: bytes, M: bytes, parts: list) -> dict:
        """Create a new instance with the given params."""
        if type(R) is not bytes or \
            len(R) != nacl.bindings.crypto_core_ed25519_BYTES or \
            not nacl.bindings.crypto_core_ed25519_is_valid_point(R):
            raise ValueError('R (aggregate nonce point) must be a valid ed25519 point')

        if type(parts) not in (list, tuple) or len(parts) < 1:
            raise ValueError('parts must be list or tuple of PartialSignature objects')

        for p in parts:
            if not isinstance(p, AbstractPartialSignature):
                raise ValueError('parts must be list or tuple of PartialSignature objects')

        # sum the partial signatures
        s = parts[0].s_i
        for i in range(1, len(parts)):
            s = nacl.bindings.crypto_core_ed25519_scalar_add(s, parts[i].s_i)

        return cls({
            'R': b64encode(R).decode(),
            's': b64encode(s).decode(),
            'M': b64encode(M).decode(),
            'parts': [b64encode(bytes(p)).decode() for p in parts]
        })

    # properties
    R = property(lambda self: self._R if hasattr(self, '_R') else None)
    s = property(lambda self: self._s if hasattr(self, '_s') else None)
    M = property(lambda self: self._M if hasattr(self, '_M') else None)
    parts = property(lambda self: self._parts if hasattr(self, '_parts') else None)
