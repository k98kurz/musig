from __future__ import annotations
from base64 import b64decode
from musig.abstractclasses import AbstractNonce, AbstractNonceCommitment
from musig.helpers import bytes_are_same, H_small


class NonceCommitment(AbstractNonceCommitment):
    """A class that handles generating, serializing, and deserializing nonce
        commitments.
    """

    def __init__(self, data: dict) -> None:
        """Initialize with a dict."""
        if type(data) is not dict:
            raise TypeError('data must be type dict')

        if 'HR' in data:
            HR = data['HR']
            self.HR = HR if type(HR) is bytes else b64decode(HR)

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on an instance."""
        if self.HR is not None:
            return self.HR
        return b''

    @classmethod
    def create(cls, nonce: AbstractNonce) -> NonceCommitment:
        """Create a new instance by hashing the given nonce."""
        if not isinstance(nonce, AbstractNonce):
            raise TypeError('nonce must be instance of AbstractNonce')

        HR = H_small(nonce.R)
        return cls({'HR': HR})

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

    @classmethod
    def from_bytes(cls, data: bytes) -> NonceCommitment:
        """Deserializes output from __bytes__."""
        if type(data) is not bytes:
            raise TypeError('data must be bytes of len 32')
        if len(data) != 32:
            raise ValueError('data must be bytes of len 32')

        return cls({'HR': data})

    @property
    def HR(self) -> bytes|None:
        """The nonce commitment bytes (hash of a nonce point)."""
        return self._HR if hasattr(self, '_HR') else None

    @HR.setter
    def HR(self, value: bytes):
        """The nonce commitment bytes (hash of a nonce point)."""
        if type(value) is not bytes:
            raise TypeError('HR must be bytes')
        if len(value) != 32:
            raise ValueError('HR value must have length 32')

        self['HR'] = value
