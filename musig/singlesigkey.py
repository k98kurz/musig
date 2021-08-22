from __future__ import annotations
from base64 import b64encode, b64decode
from json import loads
from musig.abstractclasses import AbstractSingleSigKey
from musig.helpers import bytes_are_same
from musig.nonce import Nonce
from musig.partialsignature import PartialSignature
from musig.publickey import PublicKey
from musig.signature import Signature
from nacl.signing import SigningKey
import nacl.bindings


class SingleSigKey(dict, AbstractSingleSigKey):
    """A simple-to-use class that generates 1-of-1 MuSig signatures."""

    def __init__(self, data=None) -> None:
        """Initialize using a nacl.signing.SigningKey or deserialize.
            Call with `data=SigningKey` to create a new SingleSigKey.
            Call with `data=str` or `data=bytes` to implicitly call `deserialize`.
            Call with `data=dict` to instantiate with key:value definition, where
            each value is b64 encoded.
        """
        if data is None:
            raise ValueError('cannot instantiate an empty SingleSigKey')

        if isinstance(data, str):
            data = self.deserialize(data)

        if isinstance(data, bytes) and len(data) == nacl.bindings.crypto_scalarmult_ed25519_SCALARBYTES:
            # restore from seed
            data = SigningKey(data)

        if isinstance(data, SigningKey):
            # create from a SigningKey
            self._skey = data
            self._vkey_base = data.verify_key
            self._vkey = PublicKey([self._vkey_base])

        if isinstance(data, dict):
            # deserialized json
            if 'skey' in data:
                seed = data['skey'] if isinstance(data['skey'], bytes) else b64decode(data['skey'])
                self._skey = SigningKey(seed)
                self._vkey_base = self._skey.verify_key
                self._vkey = PublicKey([self._vkey_base])

        super().__init__({
            'skey': b64encode(bytes(self._skey)).decode(),
            'vkey_base': b64encode(bytes(self._vkey_base)).decode(),
            'vkey': b64encode(bytes(self._vkey)).decode()
        })

    def __str__(self) -> str:
        """Result of calling str() on an instance."""
        if self.skey is not None:
            return '16.' + bytes(self.skey).hex()
        return ''

    def __repr__(self) -> str:
        """Result of calling repr() on an instance."""
        if self.skey is not None:
            return '64.' + b64encode(bytes(self.skey)).decode()
        return ''

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on an instance."""
        if self.skey is not None:
            return bytes(self.skey)
        return b''

    def __hash__(self) -> int:
        """Make class hashable for inclusion in sets."""
        return hash(bytes(self))

    def __eq__(self, other) -> bool:
        """Enforce timing-attack safe comparison."""
        return bytes_are_same(bytes(self), bytes(other))

    def serialize(self) -> str:
        """Return a serialized representation of the instance."""
        return repr(self)

    @classmethod
    def deserialize(cls, data) -> SingleSigKey:
        if isinstance(data, bytes):
            if len(data) != nacl.bindings.crypto_scalarmult_ed25519_SCALARBYTES:
                raise ValueError('bytes input must have length of ' +
                    str(nacl.bindings.crypto_scalarmult_ed25519_SCALARBYTES))
            return cls(data)
        if isinstance(data, str):
            # break into parts
            parts = data.split('.')
            if len(parts) < 2:
                raise ValueError('input str must have at least 2 parts delimited by .')

            if parts[0] == '16':
                seed = bytes.fromhex(parts[1])
                return cls(SigningKey(seed))
            elif parts[0] == '64':
                seed = b64decode(parts[1])
                return cls(SigningKey(seed))
            elif parts[0] == 'json':
                return cls(loads('.'.join(parts[1:])))
            else:
                raise ValueError('unknown/invalid serialization')
        else:
            raise ValueError('unknown/invalid serialization')

    def sign_message(self, M: bytes) -> Signature:
        """Sign a message."""
        nonce = Nonce()
        sig = PartialSignature.create(self.skey, nonce.r, self.vkey.L,
            self.vkey, nonce.R, M)
        return Signature.create(nonce.R, M, [sig])

    # readonly properties
    skey = property(lambda self: self._skey if hasattr(self, '_skey') else None)
    vkey = property(lambda self: self._vkey if hasattr(self, '_vkey') else None)
    vkey_base = property(lambda self: self._vkey_base if hasattr(self, '_vkey_base') else None)
