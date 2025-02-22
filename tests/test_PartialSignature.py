from context import musig
from json import dumps, loads
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
        assert inspect.isclass(musig.PartialSignature)

    def test_PartialSignature_init_raises_TypeError_when_called_with_invalid_input(self):
        with self.assertRaises(TypeError) as err:
            musig.PartialSignature('not a dict')
        assert str(err.exception) == 'data must be type dict'

    def test_PartialSignature_instances_have_correct_attributes(self):
        pkey = musig.PublicKey.create(self.verify_keys)
        n = musig.Nonce()
        psig = musig.PartialSignature.create(self.signing_keys[0], n.r, pkey.L,
            pkey, n.R, b'hello world')
        assert hasattr(psig, 'c_i') and type(psig.c_i) is bytes
        assert hasattr(psig, 's_i') and type(psig.s_i) is bytes
        assert hasattr(psig, 'R') and type(psig.R) is bytes
        assert hasattr(psig, 'M') and type(psig.M) is bytes

    def test_PartialSignature_from_bytes_raises_ValueError_or_TypeError_when_given_invalid_serialization(self):
        with self.assertRaises(TypeError) as err:
            musig.PartialSignature.from_bytes('not bytes')
        assert str(err.exception) == 'data must be bytes of len == 32 or >=96'
        with self.assertRaises(ValueError) as err:
            musig.PartialSignature.from_bytes(b'invalid bytes')
        assert str(err.exception) == 'data must be bytes of len == 32 or >=96'

    def test_PartialSignature_instances_serialize_and_deserialize_properly(self):
        pkey = musig.PublicKey.create(self.verify_keys[0:1])
        n = musig.Nonce()
        M = b'hello world'
        ps0 = musig.PartialSignature.create(self.signing_keys[0], n.r, pkey.L,
            pkey, n.R, M)
        str1 = str(ps0)
        bts = bytes(ps0)
        js = dumps(ps0)
        ps1 = musig.PartialSignature.from_str(str1)
        ps2 = musig.PartialSignature.from_bytes(bts)
        ps3 = musig.PartialSignature(loads(js))

        assert type(str1) is str and len(str1) == 96*2 + len(M)*2
        assert type(js) is str
        assert ps0 == ps1
        assert ps1 == ps2
        assert ps2 == ps3

    def test_PartialSignature_public_method_returns_instance_with_only_s_i(self):
        pkey = musig.PublicKey.create(self.verify_keys[0:1])
        n = musig.Nonce()
        M = b'hello world'
        ps0 = musig.PartialSignature.create(self.signing_keys[0], n.r, pkey.L,
            pkey, n.R, M)
        ps1 = ps0.public()

        assert ps1.s_i is not None
        assert ps1.s_i == ps0.s_i
        assert ps1.c_i is None
        assert ps1.R is None
        assert ps1.M is None

if __name__ == '__main__':
    unittest.main()
