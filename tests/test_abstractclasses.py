from __future__ import annotations
from base64 import b64decode, b64encode
from context import abstractclasses, musig
from json import dumps, loads
import musig
import nacl.bindings
import unittest


class ExtendedDictExample(abstractclasses.ExtendedDict):
    def __init__(self, data: dict = None):
        if type(data) is dict and 'stuff' in data:
            self.stuff = data['stuff']

    def __bytes__(self) -> bytes:
        if self.stuff is None:
            return b'nothing'
        if type(self.stuff) is str:
            return bytes(self.stuff, 'utf-8')
        return self.stuff if type(self.stuff) is bytes else bytes(self.stuff)

    @classmethod
    def from_bytes(cls, data: bytes) -> ExtendedDictExample:
        if type(data) is not bytes:
            raise TypeError('data must be bytes')

        return cls({
            'stuff': data
        })

    @property
    def stuff(self):
        return self._stuff if hasattr(self, '_stuff') else None

    @stuff.setter
    def stuff(self, data):
                if type(data) not in (str, bytes):
                    raise TypeError('stuff must be either str or bytes')
                self['stuff'] = data


class AbstractNonceExample(abstractclasses.AbstractNonce):
    def __init__(self, data: dict = None):
        if data is None:
            self.r = bytes.fromhex('e7b8484e312a35b8b60a8998458b5a11c7d5b39503be2855b4d54938a34fae67')
            self.R = bytes.fromhex('0a622ae3c831c30dd90e7f7e1477148be3d6725ad402f3809961f0b27d5e2c3f')

        if type(data) is dict and 'r' in data:
            self.r = data['r'] if type(data['r']) is bytes else b64decode(data['r'])

        if type(data) is dict and 'R' in data:
            self.R = data['R'] if type(data['R']) is bytes else b64decode(data['R'])

        if self.R is None and self.r is not None:
            self.R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(self.r)

    def __bytes__(self) -> bytes:
        if self.r is not None:
            return b'r' + self.r
        if self.R is not None:
            return self.R
        return b''

    @classmethod
    def from_bytes(cls, data: bytes) -> AbstractNonceExample:
        if type(data) is not bytes:
            return TypeError('data must be bytes of len 32 or 33')
        if len(data) not in (32, 33):
            return ValueError('data must be bytes of len 32 or 33')

        return cls({
            ('R' if len(data) == 32 else 'r'): data[-32:]
        })

    def __add__(self, other) -> AbstractNonceExample:
        if not isinstance(other, AbstractNonceExample):
            raise TypeError('cannot add AbstractNonceExample to non-AbstractNonceExample')
        R_sum = musig.aggregate_points([self.R, other.R])
        return self.__class__.from_bytes(R_sum)

    def copy(self) -> AbstractNonceExample:
        return self.__class__({**self})

    def public(self) -> AbstractNonceExample:
        return self.__class__({'R': self.R})

    # properties
    @property
    def r(self):
        return self._r if hasattr(self, '_r') else None

    @r.setter
    def r(self, value):
        if not isinstance(value, bytes):
            raise TypeError('r value must be bytes')
        if len(value) != 32:
            raise ValueError('r value must have length 32')

        self['r'] = value

    @property
    def R(self):
        return self._R if hasattr(self, '_R') else None

    @R.setter
    def R(self, value):
        if not isinstance(value, bytes):
            raise TypeError('R value must be bytes')
        if len(value) != 32:
            raise ValueError('R value must have length 32')

        self['R'] = value


class TestMuSigAbstractClasses(unittest.TestCase):
    """Test suite for some abstract classes.
        The purpose of this suite is to test the functionality written in the
        abstract classes themselves, not to test that every abstract class
        can be implemented properly. Everything in the module except
        ProtocolState and ProtocolError derives from ExtendedDict, so the
        primary purpose is to test the features built into that class and show
        how to implement derivative classes properly through the examples of
        ExtendedDictExample and AbstractNonceExample.
    """
    def test_class_deriving_from_ExtendedDict_cannot_set_nonproperty_keys(self):
        t = ExtendedDictExample()
        assert t is not None

        # positive case: defined property can be set
        assert hasattr(t, 'stuff')
        assert t.stuff is None
        assert 'stuff' not in t
        t['stuff'] = 'hello world'
        assert t.stuff == 'hello world'
        assert 'stuff' in t

        # negative case: undefined property cannot be set
        assert not hasattr(t, 'notstuff')
        t['notstuff'] = 'will not work'
        assert 'notstuff' not in t

    def test_class_deriving_from_ExtendedDict_sets_properties_and_key_value_pairs_properly(self):
        t = ExtendedDictExample()
        # case one: use the property setter
        t.stuff = b'hello world'
        assert t['stuff'] == b64encode(t.stuff).decode()
        # case two: use the __setitem__ implicit functionality
        t['stuff'] = b'123abc'
        assert t.stuff == b'123abc'
        assert t['stuff'] == b64encode(t.stuff).decode()

    def test_class_deriving_from_ExtendedDict_serializes_and_deserializes_properly(self):
        t0 = ExtendedDictExample({'stuff': '123'})
        t00 = ExtendedDictExample({'stuff': '321'})
        assert t0 != t00

        bts1 = bytes(t0)
        bts11 = bytes(t00)
        assert bts1 != bts11
        str1 = str(t0)
        str11 = str(t00)
        assert str1 != str11

        t1 = ExtendedDictExample.from_bytes(bts1)
        t11 = ExtendedDictExample.from_bytes(bts11)
        assert t1 != t11
        assert t1 == t0
        assert t11 == t00

        t2 = ExtendedDictExample.from_str(str1)
        t22 = ExtendedDictExample.from_str(str11)
        assert t2 != t22
        assert t2 == t0
        assert t22 == t00

    def test_class_deriving_from_ExtendedDict_is_hashable(self):
        t1 = ExtendedDictExample({'stuff':'things'})
        t2 = ExtendedDictExample({'stuff':'not things'})
        t3 = ExtendedDictExample({**t1})

        ts = set([t1, t2, t3])
        assert len(list(ts)) == 2

    def test_class_deriving_from_AbstractNonce_cannot_set_nonproperty_keys(self):
        n = AbstractNonceExample()
        assert 'r' in n and n.r is not None
        assert 'R' in n and n.R is not None
        n['notaproperty'] = 'will not be set'
        assert 'notaproperty' not in n

    def test_class_deriving_from_AbstractNonce_serializes_and_deserializes_properly(self):
        n0 = AbstractNonceExample()
        n00 = n0.public()
        bts0 = bytes(n0)
        bts00 = bytes(n00)
        str0 = str(n0)
        str00 = str(n00)
        js0 = dumps(n0)
        js00 = dumps(n00)

        n1 = AbstractNonceExample.from_bytes(bts0)
        n11 = AbstractNonceExample.from_bytes(bts00)
        n2 = AbstractNonceExample.from_str(str0)
        n22 = AbstractNonceExample.from_str(str00)
        n3 = AbstractNonceExample(loads(js0))
        n33 = AbstractNonceExample(loads(js00))

        assert n0 != n00
        assert n0 == n1
        assert n00 == n11
        assert n0 == n2
        assert n00 == n22
        assert n0 == n3
        assert n00 == n33

        assert n0.r is not None and n0.R is not None
        assert n00.r is None and n00.R is not None
        assert n1.r is not None and n1.R is not None
        assert n11.r is None and n11.R is not None
        assert n2.r is not None and n2.R is not None
        assert n22.r is None and n22.R is not None
        assert n3.r is not None and n3.R is not None
        assert n33.r is None and n33.R is not None


if __name__ == '__main__':
    unittest.main()
