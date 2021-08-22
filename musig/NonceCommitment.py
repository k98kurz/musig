from __future__ import annotations
from base64 import b64encode, b64decode
from json import loads
from musig.AbstractClasses import AbstractNonce, AbstractNonceCommitment
from musig.helpers import bytes_are_same, H_small


class NonceCommitment(dict, AbstractNonceCommitment):
    """A class that handles generating, serializing, and deserializing nonce
        commitments.
    """

    def __init__(self, data=None) -> None:
        """Initialize with a Nonce or deserialize.
            Call with `data=Nonce` to make a new NonceCommitment.
            Call with `data=bytes` to restore a NonceCommitment.
            Anything else will be sent to `deserialize`.
        """
        if data is None:
            raise ValueError('cannot instantiate an empty NonceCommitment')
        elif isinstance(data, AbstractNonce):
            self._HR = H_small(data.R)
        elif isinstance(data, bytes):
            self._HR = data
        else:
            # attempt to deserialize
            data = self.deserialize(data)
            for field in data:
                val = data[field] if type(data[field]) is bytes else b64decode(data[field])
                setattr(self, f'_{field}', val)
                self[field] = b64encode(val).decode()

        if self.HR is not None:
            self['HR'] = b64encode(self._HR).decode()

    def __repr__(self) -> str:
        """Result of calling repr() on an instance."""
        if self.HR is not None:
            return '64.' + b64encode(self.HR).decode()
        return ''

    def __str__(self) -> str:
        """Result of calling str() on an instance."""
        if self.HR is not None:
            return '16.' + self.HR.hex()
        return ''

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on an instance."""
        if self.HR is not None:
            return self.HR
        return b''

    def __hash__(self) -> int:
        """Make class hashable for inclusion in sets."""
        return hash(self._HR)

    def __eq__(self, other) -> bool:
        """Enforce timing-attack safe comparison."""
        if not isinstance(other, self.__class__):
            return False
        return bytes_are_same(bytes(self), bytes(other))

    def copy(self) -> NonceCommitment:
        """Make a copy without serializing and deserializing."""
        return NonceCommitment({**self})

    def is_valid_for(self, nonce: AbstractNonce) -> bool:
        """Checks if the NonceCommitment is valid for a specific Nonce.
            Comparison is done via xor'ing bytes to avoid timing attacks.
        """
        if not isinstance(nonce, AbstractNonce):
            raise ValueError('supplied nonce must be an instance of Nonce')

        return bytes_are_same(H_small(nonce.R), self.HR)

    def serialize(self) -> str:
        """Return a serialized representation of the instance."""
        return repr(self)

    @classmethod
    def deserialize(cls, data):
        """Deserialize some `data` into an instance.
            Acceptable types are `dict` and `str`.
            Acceptable format for `dict` is {'r': bytes, 'R': bytes}.
            Acceptable formats for `str` are '16.{hexadecimal}',
            '64.{base64}', and 'json.{json_string}'.
        """
        if isinstance(data, dict):
            if 'HR' in data:
                HR = data['HR'] if type(data['HR']) is bytes else b64decode(data['HR'])
        elif type(data) is str:
            # split the data and parse appropriately
            parts = data.split('.')
            if len(parts) < 2:
                raise ValueError('input str must have at least 2 parts delimited by .')
            if parts[0] == '64':
                HR = b64decode(parts[1])
            elif parts[0] == '16':
                HR = bytes.fromhex(parts[1])
            elif parts[0] == 'json':
                data = loads('.'.join(parts[1:]))
                if 'HR' in data:
                    HR = b64decode(data['HR'])

        if 'HR' in dir():
            return NonceCommitment(HR)
        else:
            raise ValueError('unknown serialization/input')

    # readonly property
    HR = property(lambda self: self._HR if hasattr(self, '_HR') else None)
