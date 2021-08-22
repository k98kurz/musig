from context import musig
from json import dumps, loads
from musig.Signature import Signature
from musig.PartialSignature import PartialSignature
from nacl.signing import SigningKey
import inspect
import musig
import unittest


class TestMuSigSomething(unittest.TestCase):
    """Test suite for Something."""
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
        cls.gvkey = 'eecb56e70d2405a849aa5e55b6e2f96aac2957dba72f8c289994c842e33ec477'

    def test_Signature_is_a_class(self):
        assert hasattr(musig, 'Signature')
        assert inspect.isclass(Signature)

    def test_Signature_init_raises_ValueError_when_called_without_proper_params(self):
        with self.assertRaises(ValueError):
            Signature()
        with self.assertRaises(ValueError):
            Signature(('',''))
        with self.assertRaises(ValueError):
            Signature({'a','b'})

    def test_Signature_instances_have_correct_attributes(self):
        pkey = musig.PublicKey([self.signing_keys[0].verify_key])
        n1 = musig.Nonce()
        M = b'hello world'
        ps1 = PartialSignature.create(self.signing_keys[0], n1.r, pkey.L,
            pkey, n1.R, M)
        sig = Signature.create(n1.R, M, [ps1])
        assert hasattr(sig, 'R') and type(sig.R) is bytes
        assert hasattr(sig, 'M') and type(sig.M) is bytes
        assert hasattr(sig, 's') and type(sig.s) is bytes
        assert hasattr(sig, 'parts') and type(sig.parts) is list

    def test_Signature_deserialize_raises_ValueError_when_called_with_invalid_serialization(self):
        with self.assertRaises(ValueError):
            Signature.deserialize(b'invalid bytes')
        with self.assertRaises(ValueError):
            Signature.deserialize('invalid str')
        with self.assertRaises(ValueError):
            Signature.deserialize('invalid.str')
        with self.assertRaises(ValueError):
            Signature.deserialize(('a', 'b'))
        with self.assertRaises(ValueError):
            Signature.deserialize({'a', 'b'})
        with self.assertRaises(ValueError):
            Signature.deserialize({'a': 'b'})

    def test_Signature_instances_serialize_and_deserialize_properly(self):
        pkey = musig.PublicKey([self.signing_keys[0].verify_key])
        n1 = musig.Nonce()
        M = b'hello world'
        ps1 = PartialSignature.create(self.signing_keys[0], n1.r, pkey.L,
            pkey, n1.R, M)
        sig = Signature.create(n1.R, M, [ps1])
        str1 = str(sig)
        str2 = repr(sig)
        js = dumps(sig)
        sig1 = Signature.deserialize(str1)
        sig2 = Signature.deserialize(str2)
        sig3 = Signature.deserialize('json.' + js)
        sig4 = Signature(loads(js))

        assert type(str1) is str and str1[:2] == '16'
        assert type(str2) is str and str2[:2] == '64'
        assert type(js) is str

        assert sig1 == sig2
        assert sig1 == sig3
        assert sig1 == sig4

    def test_Signature_create_raises_ValueError_when_supplied_invalid_params(self):
        M = b'hello world'
        n = musig.Nonce()
        pkey = musig.PublicKey([s.verify_key for s in self.signing_keys])
        ps = PartialSignature.create(self.signing_keys[0], n.r, pkey.L,
            pkey, n.R, M)
        with self.assertRaises(ValueError):
            Signature.create(b'invalid R bytes', M, [ps])
        with self.assertRaises(ValueError):
            Signature.create(n.R, M, [])
        with self.assertRaises(ValueError):
            Signature.create(n.R, M, [b'sdsd'])


if __name__ == '__main__':
    unittest.main()
