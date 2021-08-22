from context import musig
from enum import Enum
from json import dumps, loads
from musig.Nonce import Nonce
from musig.PartialSignature import PartialSignature
from musig.PublicKey import PublicKey
from nacl.signing import SigningKey
import inspect
import unittest


class TestMuSigPartialSignature(unittest.TestCase):
    """Test suite for PartialSignature."""
    @classmethod
    def setUpClass(cls):
        cls.seeds = [
            'bc66e048abf92e97c35f00607a9260dd8299d91e698253c1090872d7d441df80',
            'a7a4b3a2afae8026fb6d523f06f67e5e69ca8e583881ca34574a8e6a9658eaec',
            'a5f496e55953105c5f80939f7a7794edcfd89997e801b6365effd35af1150b02'
        ]
        cls.seeds = [bytes.fromhex(seed) for seed in cls.seeds]
        cls.signing_keys = [SigningKey(seed) for seed in cls.seeds]
        cls.verify_keys = [sk.verify_key for sk in cls.signing_keys]

    def test_PartialSignature_is_a_class(self):
        assert inspect.isclass(PartialSignature)

    def test_PartialSignature_init_raises_ValueError_when_called_without_param(self):
        with self.assertRaises(ValueError):
            PartialSignature()

    def test_PartialSignature_instances_have_correct_attributes(self):
        pkey = PublicKey(self.verify_keys)
        n = Nonce()
        psig = PartialSignature.create(self.signing_keys[0], n.r, pkey.L,
            pkey, n.R, b'hello world')
        assert hasattr(psig, 'c_i') and type(psig.c_i) is bytes
        assert hasattr(psig, 's_i') and type(psig.s_i) is bytes
        assert hasattr(psig, 'R') and type(psig.R) is bytes
        assert hasattr(psig, 'M') and type(psig.M) is bytes

    def test_PartialSignature_deserialize_raises_ValueError_when_given_invalid_serialization(self):
        with self.assertRaises(ValueError):
            PartialSignature.deserialize(b'invalid bytes')
        with self.assertRaises(ValueError):
            PartialSignature.deserialize('invalid str')
        with self.assertRaises(ValueError):
            PartialSignature.deserialize('invalid.str')
        with self.assertRaises(ValueError):
            PartialSignature.deserialize([])
        with self.assertRaises(ValueError):
            PartialSignature.deserialize(('',''))
        with self.assertRaises(ValueError):
            PartialSignature.deserialize({'a','b'})
        with self.assertRaises(ValueError):
            PartialSignature.deserialize({'a':'b'})

    def test_PartialSignature_instances_serialize_and_deserialize_properly(self):
        pkey = PublicKey(self.verify_keys)
        n = Nonce()
        ps0 = PartialSignature.create(self.signing_keys[0], n.r, pkey.L,
            pkey, n.R, b'hello world')
        str1 = str(ps0)
        str2 = repr(ps0)
        js = dumps(ps0)
        ps1 = PartialSignature(str1)
        ps2 = PartialSignature(str2)
        ps3 = PartialSignature(loads(js))
        ps4 = PartialSignature('json.' + js)

        assert type(str1) is str and str1[:2] == '16'
        assert type(str2) is str and str2[:2] == '64'
        assert type(js) is str
        assert ps0 == ps1
        assert ps1 == ps2
        assert ps2 == ps3
        assert ps3 == ps4

    def test_PartialSignature_instances_can_be_members_of_sets(self):
        pkey = PublicKey(self.verify_keys)
        n1, n2, n3 = Nonce(), Nonce(), Nonce()
        ps1 = PartialSignature.create(self.signing_keys[0], n1.r, pkey.L,
            pkey, n1.R, b'hello world')
        ps2 = PartialSignature.create(self.signing_keys[1], n2.r, pkey.L,
            pkey, n2.R, b'hello world')
        ps3 = PartialSignature.create(self.signing_keys[2], n3.r, pkey.L,
            pkey, n3.R, b'hello world')
        ps33 = PartialSignature(str(ps3))

        pses = set([ps1, ps2, ps3, ps33])
        assert len(pses) == 3


if __name__ == '__main__':
    unittest.main()
