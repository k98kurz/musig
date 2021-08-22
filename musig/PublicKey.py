from __future__ import annotations
from base64 import b64encode, b64decode
from json import loads
from musig.helpers import aggregate_points, bytes_are_same, H_agg, H_sig, H_small
from musig.Signature import Signature
from nacl.signing import VerifyKey
import nacl.bindings


class PublicKey(dict):
    """A class that aggregates the public keys of participants of a Session
        and verifies Signatures.
    """

    def __init__(self, data=None) -> None:
        """Initialize the instance using the given data."""
        if type(data) not in [bytes, str, list, dict]:
            raise ValueError('input data must be bytes, str, list, or dict')

        if type(data) is list:
            # parse the data as a list of participant keys
            self._vkeys = [vk if isinstance(vk, VerifyKey) else VerifyKey(vk) for vk in data]
            self['vkeys'] = [b64encode(bytes(vk)).decode() for vk in self._vkeys]

        if type(data) is dict:
            super().__init__(data)
            if 'vkeys' in data:
                self._vkeys = [VerifyKey(b64decode(vk)) for vk in data['vkeys']]
            if 'gvkey' in data:
                self._gvkey = b64decode(data['gvkey'])
            if 'L' in data:
                self._L = b64decode(data['L'])

        if type(data) is bytes:
            # instantiate with the bytes of the gvkey
            self._gvkey = data
            self['gvkey'] = b64encode(self._gvkey).decode()

        if type(data) is str:
            # try to deserialize into a dict
            data = self.deserialize(data)
            super().__init__(data)
            if 'vkeys' in data:
                self._vkeys = [VerifyKey(b64decode(vk)) for vk in data['vkeys']]
            if 'gvkey' in data:
                self._gvkey = b64decode(data['gvkey'])
            if 'L' in data:
                self._L = b64decode(data['L'])

        if hasattr(self, '_vkeys'):
            # derive L and gvkey from participant keys if necessary
            if not hasattr(self, '_L'):
                self._L = self.encode_key_set(self._vkeys)
                self['L'] = b64encode(self._L).decode()
            if not hasattr(self, '_gvkey'):
                self._gvkey = self.aggregate_public_keys(self._vkeys, self._L)
                self['gvkey'] = b64encode(self._gvkey).decode()

    def __repr__(self) -> str:
        """Return the base64 encoded component keys or the aggregate public key."""
        if len(self._vkeys) > 0:
            return '64i.' + '.'.join([b64encode(bytes(vk)).decode() for vk in self._vkeys])
        return '64.' + b64encode(self._gvkey).decode()

    def __str__(self) -> str:
        """Return the hex encoded component keys or the aggregate public key."""
        if len(self._vkeys) > 0:
            return '16i.' + '.'.join([bytes(vk).hex() for vk in self._vkeys])
        return '16.' + self._gvkey.hex()

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on an instance."""
        return self._gvkey

    def __hash__(self) -> int:
        """Make class hashable for inclusion in sets."""
        return hash(bytes(self))

    def __eq__(self, other) -> bool:
        """Enforce timing-attack safe comparison."""
        if not isinstance(other, self.__class__):
            return False
        return bytes_are_same(bytes(self), bytes(other))

    def serialize(self) -> str:
        """Return the base64 encoded component keys or the aggregate public key."""
        return repr(self)

    @classmethod
    def deserialize(cls, data) -> PublicKey:
        """Deserialize some `data` into an instance.
            The type of `data` must be `str`.
            Acceptable formats are '16.{hexadecimal_gvkey}', '16i.{hex.parts}',
            '64.{b64_gvkey}', '64i.{b64.parts}', and 'json.{json_string}'. Parts
            for a hex or b64 encoded serialization are the participant public
            keys delimited by '.'.
        """
        if isinstance(data, str):
            # split the data and parse appropriately
            parts = data.split('.')
            if len(parts) < 2:
                raise ValueError('input str must have at least 2 parts delimited by .')
            elif parts[0] == '64' and len(parts) == 2:
                # parse base64 aggregate key
                return PublicKey({'gvkey': parts[1]})
            elif parts[0] == '64i' and len(parts) >= 2:
                # parse base64 component keys
                return PublicKey({'vkeys': parts[1:]})
            elif parts[0] == '16' and len(parts) == 2:
                # parse hex aggregate key
                return PublicKey({'gvkey': b64encode(bytes.fromhex(parts[1]))})
            elif parts[0] == '16i' and len(parts) >= 2:
                return PublicKey({'vkeys': [b64encode(bytes.fromhex(vk)) for vk in parts[1:]]})
            elif parts[0] == 'json':
                return PublicKey(loads('.'.join(parts[1:])))
            else:
                raise ValueError('unknown/invalid serialization')

    def verify(self, sig: Signature) -> bool:
        """Verify a signature is valid for this PublicKey."""
        X = bytes(self.gvkey)
        s = sig.s
        R = sig.R
        M = sig.M

        c = H_sig(X, R, M)
        gs = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(s)
        RXc = nacl.bindings.crypto_scalarmult_ed25519_noclamp(c, X)
        RXc = nacl.bindings.crypto_core_ed25519_add(R, RXc)

        return bytes_are_same(gs, RXc)

    @classmethod
    def aggregate_public_keys(cls, vkeys: list, key_set_L=None) -> bytes:
        """Calculate the aggregate public key."""
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
        """Transform the public key with the key set modifier."""
        a_i = H_agg(key_set_L, bytes(vkey))
        return nacl.bindings.crypto_scalarmult_ed25519_noclamp(a_i, bytes(vkey))

    @classmethod
    def encode_key_set(cls, vkeys: list) -> bytes:
        """Sort the participant keys and hash them together."""
        vkeys = [bytes(vk) if type(vk) is VerifyKey else vk for vk in vkeys]
        vkeys.sort()
        return H_small(*vkeys)

    # define some properties
    L = property(lambda self: self._L if hasattr(self, '_L') else None)
    gvkey = property(lambda self: self._gvkey if hasattr(self, '_gvkey') else None)
    vkeys = property(lambda self: self._vkeys if hasattr(self, '_vkeys') else None)
