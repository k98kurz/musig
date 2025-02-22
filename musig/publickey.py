from __future__ import annotations
from base64 import b64decode
from musig.abstractclasses import AbstractPublicKey, AbstractSignature
from musig.helpers import aggregate_points, bytes_are_same, H_agg, H_sig, H_small
from nacl.signing import VerifyKey
import nacl.bindings


class PublicKey(AbstractPublicKey):
    """A class that aggregates the public keys of participants of a Session
        and verifies Signatures.
    """

    def __init__(self, data: dict = None) -> None:
        """Initialize the instance using the given data.
            Initialize with `{'vkeys': list_of_vkeys}` to create a PublicKey from
            participant keys. Initialize with `{'gvkey': bytes}` to restore just
            enough to verify signatures.
        """
        if data is None:
            raise ValueError('cannot instantiate empty PublicKey')

        if type(data) is not dict:
            raise TypeError('input data must be dict')

        if 'vkeys' in data:
            self.vkeys = tuple([vk if isinstance(vk, VerifyKey) else VerifyKey(b64decode(vk)) for vk in data['vkeys']])
        if 'gvkey' in data:
            self.gvkey = data['gvkey'] if type(data['gvkey']) is bytes else b64decode(data['gvkey'])
        if 'L' in data:
            self.L = data['L'] if type(data['L']) is bytes else b64decode(data['L'])

        if len(self.vkeys) > 0 and self.L is None:
            self.L = self.encode_key_set(self.vkeys)

        if len(self.vkeys) > 0 and self.gvkey is None:
            self.gvkey = self.aggregate_public_keys(self.vkeys, self.L)

    def __bytes__(self) -> bytes:
        """Serialize to bytes by calling bytes() on an instance."""
        if len(self.vkeys) > 0:
            return b''.join([bytes(vk) for vk in self.vkeys])
        return self.gvkey

    @classmethod
    def from_bytes(cls, data: bytes) -> PublicKey:
        """Deserialize an instance from bytes."""
        if type(data) is not bytes:
            raise TypeError('cannot call from_bytes with non-bytes param')
        if len(data) < 32 or len(data) % 32 > 0:
            raise ValueError('byte length must be a multiple of 32')

        gvkey = data[:32]
        data = data[32:]
        vkeys = [gvkey]

        while len(data) > 0:
            vkeys.append(data[:32])
            data = data[32:]

        vkeys = [VerifyKey(vk) for vk in vkeys]

        return cls({'vkeys': vkeys}) if len(vkeys) > 1 else cls({'gvkey': gvkey})

    @classmethod
    def create(cls, vkeys: list[VerifyKey|bytes]) -> PublicKey:
        """Create a new PublicKey from a list or tuple of participant VerifyKeys."""
        if type(vkeys) not in (list, tuple):
            raise TypeError('vkeys must be list or tuple of VerifyKey')

        for vk in vkeys:
            if not isinstance(vk, VerifyKey):
                raise TypeError('vkeys must be list or tuple of VerifyKey')

        L = cls.encode_key_set(vkeys)
        gvkey = cls.aggregate_public_keys(vkeys, L)

        return cls({
            'vkeys': tuple(vkeys),
            'L': L,
            'gvkey': gvkey
        })

    def public(self) -> PublicKey:
        """Return a copy of the instance with only the public value (gvkey)."""
        return self.__class__({
            'gvkey': self.gvkey
        })

    def verify(self, sig: AbstractSignature) -> bool:
        """Verify a signature is valid for this PublicKey."""
        X = bytes(self.gvkey)
        s = sig.s
        R = sig.R
        M = sig.M

        c = H_sig(R, X, M)
        gs = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(s)
        RXc = nacl.bindings.crypto_scalarmult_ed25519_noclamp(c, X)
        RXc = nacl.bindings.crypto_core_ed25519_add(R, RXc)

        return bytes_are_same(gs, RXc)

    @classmethod
    def aggregate_public_keys(cls, vkeys: list[VerifyKey|bytes], key_set_L: bytes = None) -> bytes:
        """Calculate the aggregate public key from the participant keys."""
        # parse arguments
        vkeys = [vk if type(vk) is VerifyKey else VerifyKey(vk) for vk in vkeys]
        key_set_L = cls.encode_key_set(vkeys) if key_set_L is None else key_set_L

        # transform vkeys
        vkeys_transformed = [cls.pre_agg_key_transform(vk, key_set_L) for vk in vkeys]

        # sum the transformed keys
        sum = aggregate_points(vkeys_transformed)

        # return the aggregate vkey
        return sum

    @classmethod
    def pre_agg_key_transform(cls, vkey: VerifyKey, key_set_L: bytes) -> bytes:
        """Transform a participant VerifyKey prior to calculating the aggregate
            public key. This is called by aggregate_public_keys on every
            participant VerifyKey.
        """
        a_i = H_agg(key_set_L, bytes(vkey))
        return nacl.bindings.crypto_scalarmult_ed25519_noclamp(a_i, bytes(vkey))

    @classmethod
    def encode_key_set(cls, vkeys: list) -> bytes:
        """Sort the participant keys into a deterministic order, then hash the
            list to produce the keyset encoding (L).
        """
        vkeys = [bytes(vk) if type(vk) is VerifyKey else vk for vk in vkeys]
        vkeys.sort()
        return H_small(*vkeys)

    # define some properties
    @property
    def L(self) -> bytes:
        """The keyset encoding used for calculating partial signatures."""
        return self._L if hasattr(self, '_L') else None

    @L.setter
    def L(self, data: bytes):
        """The keyset encoding used for calculating partial signatures."""
        if type(data) is not bytes:
            raise TypeError('L must be bytes of len 32')
        if len(data) != 32:
            raise ValueError('L must be bytes of len 32')

        self['L'] = data

    @property
    def gvkey(self) -> bytes:
        """The bytes of the aggregate key (denoted X in the MuSig paper)."""
        return self._gvkey if hasattr(self, '_gvkey') else None

    @gvkey.setter
    def gvkey(self, data: bytes):
        """The bytes of the aggregate key (denoted X in the MuSig paper)."""
        if type(data) is not bytes:
            raise TypeError('gvkey must be bytes of len 32')
        if len(data) != 32:
            raise ValueError('gvkey must be bytes of len 32')

        self['gvkey'] = data

    @property
    def vkeys(self) -> tuple[VerifyKey, ...]:
        """Tuple of untransformed participant VerifyKeys."""
        return self._vkeys if hasattr(self, '_vkeys') else tuple()

    @vkeys.setter
    def vkeys(self, data: list[VerifyKey]):
        """Tuple of untransformed participant VerifyKeys."""
        if type(data) not in (list, tuple):
            raise TypeError('vkeys must be list or tuple of VerifyKeys')
        for vk in data:
            if not isinstance(vk, VerifyKey):
                raise TypeError('vkeys must be list or tuple of VerifyKeys')

        self['vkeys'] = tuple(data)
