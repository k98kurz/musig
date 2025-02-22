from __future__ import annotations
from base64 import b64decode
from musig.abstractclasses import AbstractSignature, AbstractPartialSignature
from musig.partialsignature import PartialSignature
import nacl.bindings


class Signature(AbstractSignature):
    """A class that sums PartialSignatures into a full Signature."""
    def __init__(self, data: dict = None) -> None:
        """Initialize an instance. Initialize with `{'parts': list_of_partial_sigs,
            'M': bytes, 'R': bytes}` to create a new signature from parts. Initialize
            with `{'s': bytes, 'R': bytes, 'M': bytes}` to restore a signature.
        """
        if not isinstance(data, dict):
            raise TypeError('data for initialization must be of type dict')

        if 'R' in data:
            self.R = data['R'] if type(data['R']) is bytes else b64decode(data['R'])
        if 'M' in data:
            self.M = data['M'] if type(data['M']) is bytes else b64decode(data['M'])
        if 's' in data:
            self.s = data['s'] if type(data['s']) is bytes else b64decode(data['s'])
        if 'parts' in data:
            parts = [PartialSignature.from_bytes(p if type(p) is bytes else b64decode(p)) for p in data['parts']]
            self.parts = parts

        if len(self.parts) > 0 and self.R is not None and self.M is not None and self.s is None:
            sig = self.create(self.R, self.M, self.parts)
            self.s = sig.s

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on an instance; i.e. serialize to bytes."""
        return self.R + self.s + self.M

    @classmethod
    def from_bytes(cls, data: bytes) -> Signature:
        """Deserializes output from __bytes__."""
        if type(data) is not bytes:
            raise TypeError('data must be bytes with length at least 65')
        if len(data) < 65:
            raise ValueError('data must be bytes with length at least 65')

        R = data[:32]
        s = data[32:64]
        M = data[64:]

        return cls({
            'R': R,
            's': s,
            'M': M
        })

    @classmethod
    def create(cls, R: bytes, M: bytes, parts: list[AbstractPartialSignature]) -> Signature:
        """Create a new instance using the aggregate nonce point (R), the
            message (M), and the list/tuple of partial signatures (scalars s_i).
        """
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
            'R': R,
            's': s,
            'M': M,
            'parts': [bytes(p) for p in parts]
        })

    @property
    def R(self) -> bytes:
        """Aggregate nonce point."""
        return self._R if hasattr(self, '_R') else None

    @R.setter
    def R(self, data: bytes):
        """Aggregate nonce point."""
        if type(data) is not bytes:
            raise TypeError('R must be bytes of len 32')
        if len(data) != 32:
            raise ValueError('R must be bytes of len 32')

        self['R'] = data

    @property
    def s(self) -> bytes:
        """Aggregate signature made from summing partial signatures."""
        return self._s if hasattr(self, '_s') else None

    @s.setter
    def s(self, data: bytes):
        """Aggregate signature made from summing partial signatures."""
        if type(data) is not bytes:
            raise TypeError('s must be bytes of len 32')
        if len(data) != 32:
            raise ValueError('s must be bytes of len 32')

        self['s'] = data

    @property
    def M(self) -> bytes:
        """Message to be signed."""
        return self._M if hasattr(self, '_M') else None

    @M.setter
    def M(self, data: bytes):
        """Message to be signed."""
        if type(data) not in (bytes, str):
            raise TypeError('M must be bytes or str')

        self['M'] = data if type(data) is bytes else bytes(data, 'utf-8')

    @property
    def parts(self) -> tuple[AbstractPartialSignature, ...]:
        """Tuple of partial signatures summed together to create the signature."""
        return self._parts if hasattr(self, '_parts') else tuple()

    @parts.setter
    def parts(self, data: list[AbstractPartialSignature]):
        """Tuple of partial signatures summed together to create the signature."""
        if type(data) not in (list, tuple):
            raise TypeError('parts must be list or tuple of PartialSignatures')
        for ps in data:
            if not isinstance(ps, AbstractPartialSignature):
                raise TypeError('parts must be list or tuple of PartialSignatures')

        self['parts'] = tuple(data)
