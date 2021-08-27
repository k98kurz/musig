from context import musig
from json import dumps, loads
from nacl.signing import SigningKey
import inspect
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
        assert inspect.isclass(musig.Signature)

    def test_Signature_init_raises_TypeError_when_called_without_proper_params(self):
        with self.assertRaises(TypeError) as err:
            musig.Signature()
        assert str(err.exception) == 'data for initialization must be of type dict'
        with self.assertRaises(TypeError):
            musig.Signature('not a dict')
        assert str(err.exception) == 'data for initialization must be of type dict'

    def test_Signature_instances_have_correct_attributes(self):
        pkey = musig.PublicKey.create([self.signing_keys[0].verify_key])
        n1 = musig.Nonce()
        M = b'hello world'
        ps1 = musig.PartialSignature.create(self.signing_keys[0], n1.r, pkey.L,
            pkey, n1.R, M)
        sig = musig.Signature.create(n1.R, M, [ps1])
        assert hasattr(sig, 'R') and type(sig.R) is bytes
        assert hasattr(sig, 'M') and type(sig.M) is bytes
        assert hasattr(sig, 's') and type(sig.s) is bytes
        assert hasattr(sig, 'parts') and type(sig.parts) is tuple

    def test_Signature_from_bytes_raises_ValueError_or_TypeError_when_called_with_invalid_serialization(self):
        with self.assertRaises(TypeError) as err:
            musig.Signature.from_bytes('not bytes')
        assert str(err.exception) == 'data must be bytes with length at least 65'
        with self.assertRaises(ValueError) as err:
            musig.Signature.from_bytes(b'invalid bytes')
        assert str(err.exception) == 'data must be bytes with length at least 65'

    def test_Signature_instances_serialize_and_deserialize_properly(self):
        pkey = musig.PublicKey.create([self.signing_keys[0].verify_key])
        n1 = musig.Nonce()
        M = b'hello world'
        ps1 = musig.PartialSignature.create(self.signing_keys[0], n1.r, pkey.L,
            pkey, n1.R, M)
        sig0 = musig.Signature.create(n1.R, M, [ps1])
        bts1 = bytes(sig0)
        str2 = str(sig0)
        js = dumps(sig0)
        sig1 = musig.Signature.from_bytes(bts1)
        sig2 = musig.Signature.from_str(str2)
        sig3 = musig.Signature(loads(js))

        assert type(bts1) is bytes and len(bts1) == 64 + len(M)
        assert type(str2) is str and len(str2) == 2*len(bts1)
        assert type(js) is str

        assert sig1 == sig2
        assert sig1 == sig3

    def test_Signature_create_raises_ValueError_when_supplied_invalid_params(self):
        M = b'hello world'
        n = musig.Nonce()
        pkey = musig.PublicKey.create([s.verify_key for s in self.signing_keys])
        ps = musig.PartialSignature.create(self.signing_keys[0], n.r, pkey.L,
            pkey, n.R, M)
        with self.assertRaises(ValueError):
            musig.Signature.create(b'invalid R bytes', M, [ps])
        with self.assertRaises(ValueError):
            musig.Signature.create(n.R, M, [])
        with self.assertRaises(ValueError):
            musig.Signature.create(n.R, M, [b'sdsd'])


if __name__ == '__main__':
    unittest.main()
