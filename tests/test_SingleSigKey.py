from context import musig
from json import dumps, loads
from nacl.signing import SigningKey, VerifyKey
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

    def test_SingleSigKey_is_a_class(self):
        assert hasattr(musig, 'SingleSigKey')
        assert inspect.isclass(musig.SingleSigKey)

    def test_SingleSigKey_init_raises_ValueError_when_given_None_param(self):
        with self.assertRaises(ValueError):
            musig.SingleSigKey()
        with self.assertRaises(ValueError):
            musig.SingleSigKey(None)

    def test_SingleSigKey_instances_have_correct_attributes(self):
        ssk = musig.SingleSigKey(self.signing_keys[0])
        assert hasattr(ssk, 'skey') and isinstance(ssk.skey, SigningKey)
        assert hasattr(ssk, 'vkey') and isinstance(ssk.vkey, musig.PublicKey)
        assert hasattr(ssk, 'vkey_base') and isinstance(ssk.vkey_base, VerifyKey)
        assert ssk.skey == self.signing_keys[0]
        assert ssk.vkey_base == self.signing_keys[0].verify_key

    def test_SingleSigKey_deserialize_raises_ValueError_for_invalid_params(self):
        with self.assertRaises(ValueError):
            musig.SingleSigKey.deserialize(b'invalid bytes')
        with self.assertRaises(ValueError):
            musig.SingleSigKey.deserialize('invalid str')
        with self.assertRaises(ValueError):
            musig.SingleSigKey.deserialize('invalid.str')
        with self.assertRaises(ValueError):
            musig.SingleSigKey.deserialize(('a', 'b'))
        with self.assertRaises(ValueError):
            musig.SingleSigKey.deserialize({'a', 'b'})
        with self.assertRaises(ValueError):
            musig.SingleSigKey.deserialize({'a': 'b'})

    def test_SingleSigKey_instances_serialize_and_deserialize_properly(self):
        ssk0 = musig.SingleSigKey(self.signing_keys[0])
        str1 = str(ssk0)
        str2 = repr(ssk0)
        js = dumps(ssk0)
        ssk1 = musig.SingleSigKey(str1)
        ssk2 = musig.SingleSigKey(str2)
        ssk3 = musig.SingleSigKey('json.' + js)
        ssk4 = musig.SingleSigKey(loads(js))

        assert type(str1) is str and str1[:2] == '16'
        assert type(str2) is str and str2[:2] == '64'
        assert type(js) is str

        assert ssk1 == ssk2
        assert ssk1 == ssk3
        assert ssk1 == ssk4

    def test_SingleSigKey_sign_message_method_returns_Signature(self):
        ssk = musig.SingleSigKey(self.signing_keys[0])
        sig = ssk.sign_message(b'hello world')
        assert isinstance(sig, musig.Signature)

    def test_SingleSigKey_signatures_are_verified_by_relevant_PublicKey(self):
        ssk = musig.SingleSigKey(self.signing_keys[0])
        sig = ssk.sign_message(b'hello world')
        assert ssk.vkey.verify(sig)


if __name__ == '__main__':
    unittest.main()
