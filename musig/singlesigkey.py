from __future__ import annotations
from base64 import b64decode
from musig.abstractclasses import AbstractSingleSigKey
from musig.nonce import Nonce
from musig.partialsignature import PartialSignature
from musig.publickey import PublicKey
from musig.signature import Signature
from nacl.signing import SigningKey, VerifyKey
import nacl.bindings


class SingleSigKey(AbstractSingleSigKey):
    """A simple-to-use class that generates 1-of-1 MuSig signatures."""

    def __init__(self, data: dict = None) -> None:
        """Initialize using a nacl.signing.SigningKey or deserialize.
            Call with `{'skey':SigningKey}` to create a new SingleSigKey.
            Call with a dict containing json.loads output from a json.dumps
            serialization to restore an instance.
        """
        if data is None:
            raise ValueError('cannot instantiate an empty SingleSigKey')

        if not isinstance(data, dict):
            raise TypeError('data for initialization must be of type dict')

        if 'skey' in data:
            if isinstance(data['skey'], SigningKey):
                self.skey = data['skey']
            else:
                seed = data['skey'] if isinstance(data['skey'], bytes) else b64decode(data['skey'])
                self.skey = SigningKey(seed)

        if 'vkey_base' in data:
            if isinstance(data['vkey_base'], VerifyKey):
                self.vkey_base = data['vkey_base']
            else:
                vkey_base = data['vkey_base'] if type(data['vkey_base']) is bytes else b64decode(data['vkey_base'])
                self.vkey_base = VerifyKey(vkey_base)

        if 'vkey' in data:
            if isinstance(data['vkey'], PublicKey):
                self.vkey = data['vkey']
            else:
                vkey = data['vkey'] if type(data['vkey']) is bytes else b64decode(data['vkey'])
                self.vkey = PublicKey.from_bytes(vkey)

        if self.vkey_base is None and self.skey is not None:
            self.vkey_base = self.skey.verify_key

        if self.vkey is None and self.vkey_base is not None:
            self.vkey = PublicKey.create([self.vkey_base])

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on an instance; i.e. serialize to bytes."""
        if self.skey is not None:
            return bytes(self.skey)
        return b''

    @classmethod
    def from_bytes(cls, data: bytes) -> SingleSigKey:
        """Deserializes output from __bytes__."""
        if type(data) is not bytes:
            raise TypeError('bytes input must have length of ' +
                    str(nacl.bindings.crypto_scalarmult_ed25519_SCALARBYTES))
        if len(data) != nacl.bindings.crypto_scalarmult_ed25519_SCALARBYTES:
            raise ValueError('bytes input must have length of ' +
                str(nacl.bindings.crypto_scalarmult_ed25519_SCALARBYTES))

        return cls({'skey': SigningKey(data)})

    def sign_message(self, M: bytes) -> Signature:
        """Sign a message (M) and return a Signature."""
        nonce = Nonce()
        sig = PartialSignature.create(self.skey, nonce.r, self.vkey.L,
            self.vkey, nonce.R, M)
        return Signature.create(nonce.R, M, [sig])

    @property
    def skey(self) -> SigningKey|None:
        """The SigningKey used for creating signatures."""
        return self._skey if hasattr(self, '_skey') else None

    @skey.setter
    def skey(self, data: SigningKey):
        """The SigningKey used for creating signatures."""
        if not isinstance(data, SigningKey):
            raise TypeError('skey must be SigningKey')

        self['skey'] = data

    @property
    def vkey(self) -> PublicKey|None:
        """The aggregate public key for verifying signatures."""
        return self._vkey if hasattr(self, '_vkey') else None

    @vkey.setter
    def vkey(self, data: PublicKey):
        """The aggregate public key for verifying signatures."""
        if not isinstance(data, PublicKey):
            raise TypeError('vkey must be PublicKey')

        self['vkey'] = data

    @property
    def vkey_base(self) -> VerifyKey|None:
        """The VerifyKey base used to calculate the aggregate public key."""
        return self._vkey_base if hasattr(self, '_vkey_base') else None

    @vkey_base.setter
    def vkey_base(self, data: VerifyKey):
        """The VerifyKey base used to calculate the aggregate public key."""
        if not isinstance(data, VerifyKey):
            raise TypeError('vkey_base must be VerifyKey')

        self['vkey_base'] = data
