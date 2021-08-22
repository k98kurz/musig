from __future__ import annotations
from base64 import b64encode, b64decode
from json import loads
from musig import PublicKey, bytes_are_same, derive_key_from_seed, derive_challenge
from nacl.signing import SigningKey
import nacl.bindings


class PartialSignature(dict):
    """A class that handles creation, serialization, and deserialization of
        partial signatures used to create MuSig aggregate signatures.
    """
    def __init__(self, data=None) -> None:
        """Initialize an instance with params for the `create` method or
            deserialize.
            Call with `data=(skey: SigningKey, r: bytes, L: bytes, X: PublicKey,
            R: bytes, M: bytes)` to create a new PartialSignature.
            Call with `data=str` or `data=bytes` to implicitly call `deserialize`.
            Call with `data=dict` to instantiate with key:value definition, where
            each value is b64 encoded.
        """
        if data is None:
            raise ValueError('cannot instantiate PartialSignature with None')

        if type(data) in [list, tuple] and len(data) == 6:
            data = self.create(*data)

        if type(data) in (bytes, str):
            data = self.deserialize(data)

        if isinstance(data, dict):
            super().__init__(data)
            if 'c_i' in data:
                self._c_i = b64decode(data['c_i'])
            if 's_i' in data:
                self._s_i = b64decode(data['s_i'])
            if 'R' in data:
                self._R = b64decode(data['R'])
            if 'M' in data:
                self._M = b64decode(data['M'])

    def __str__(self) -> str:
        """Result of calling str() on an instance."""
        parts = [
            self.c_i.hex(),
            self.s_i.hex(),
            self.R.hex(),
            self.M.hex(),
        ]
        return '16.' + '.'.join(parts)

    def __repr__(self) -> str:
        """Result of calling repr() on an instance."""
        parts = [
            b64encode(self.c_i).decode(),
            b64encode(self.s_i).decode(),
            b64encode(self.R).decode(),
            b64encode(self.M).decode(),
        ]
        return '64.' + '.'.join(parts)

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on an instance."""
        return self.c_i + self.s_i + self.R + self.M

    def __hash__(self) -> int:
        """Make class hashable for inclusion in sets."""
        return hash(self.c_i + self.s_i + self.R + self.M)

    def __eq__(self, other) -> bool:
        """Enforce timing-attack safe comparison."""
        if not isinstance(other, self.__class__):
            return False
        return bytes_are_same(bytes(self), bytes(other))

    def serialize(self) -> str:
        """Return a serialized representation of the instance."""
        return repr(self)

    @classmethod
    def deserialize(cls, data) -> PartialSignature:
        """Deserialize some `data` into an instance.
            Acceptable types are `str` and `bytes`.
            Acceptable formats for `str` are '16.{hexadecimal.parts}',
            '64.{base64.parts}', and 'json.{json_string}'.
            Parts for a hex or b64 encoded serialization are c_i, s_i,
            R, and M delimited by '.'.
            Acceptable format for `bytes` is c_i+s_i+R+M, where
            c_i, s_i, and R each has len=32.
        """
        if type(data) is bytes:
            if len(data) < 32*3+1:
                raise ValueError('bytes must be at least 97 length')
            c_i = data[:32]
            s_i = data[32:64]
            R = data[64:96]
            M = data[96:]
            return cls({
                'c_i': b64encode(c_i).decode(),
                's_i': b64encode(s_i).decode(),
                'R': b64encode(R).decode(),
                'M': b64encode(M).decode(),
            })
        elif type(data) is str:
            # split into parts
            parts = data.split('.')
            if parts[0] != 'json' and len(parts) != 5:
                raise ValueError('input str must have 5 parts delimited by .')
            if parts[0] == '16':
                c_i = bytes.fromhex(parts[1])
                s_i = bytes.fromhex(parts[2])
                R = bytes.fromhex(parts[3])
                M = bytes.fromhex(parts[4])
                return cls({
                    'c_i': b64encode(c_i).decode(),
                    's_i': b64encode(s_i).decode(),
                    'R': b64encode(R).decode(),
                    'M': b64encode(M).decode(),
                })
            elif parts[0] == '64':
                return cls({
                    'c_i': parts[1],
                    's_i': parts[2],
                    'R': parts[3],
                    'M': parts[4],
                })
            elif parts[0] == 'json':
                return cls(loads('.'.join(parts[1:])))
            else:
                raise ValueError('unknown/invalid serialization')
        else:
            raise ValueError('unknown/invalid serialization')

    @classmethod
    def create(cls, skey: SigningKey, r: bytes, L: bytes, X: PublicKey,
            R: bytes, M: bytes) -> dict:
        """Create a partial signature from skey, r (nonce), L (key set encoding),
            X (aggregate key), R (aggregate public nonce), and M (message).
        """
        x_i = derive_key_from_seed(bytes(skey))
        c_i = derive_challenge(L, bytes(skey.verify_key), bytes(X), R, M)
        s_i = nacl.bindings.crypto_core_ed25519_scalar_mul(c_i, x_i)
        s_i = nacl.bindings.crypto_core_ed25519_scalar_add(r, s_i)

        return cls({
            'c_i': b64encode(c_i).decode(),
            's_i': b64encode(s_i).decode(),
            'R': b64encode(R).decode(),
            'M': b64encode(M).decode(),
        })

    c_i = property(lambda self: self._c_i if hasattr(self, '_c_i') else None)
    s_i = property(lambda self: self._s_i if hasattr(self, '_s_i') else None)
    R = property(lambda self: self._R if hasattr(self, '_R') else None)
    M = property(lambda self: self._M if hasattr(self, '_R') else None)
