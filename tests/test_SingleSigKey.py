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
        with self.assertRaises(ValueError) as err:
            musig.SingleSigKey()
        assert str(err.exception) == 'cannot instantiate an empty SingleSigKey'
        with self.assertRaises(TypeError) as err:
            musig.SingleSigKey('not a dict')
        assert str(err.exception) == 'data for initialization must be of type dict'

    def test_SingleSigKey_instances_have_correct_attributes(self):
        ssk = musig.SingleSigKey({'skey': self.signing_keys[0]})
        assert hasattr(ssk, 'skey') and isinstance(ssk.skey, SigningKey)
        assert hasattr(ssk, 'vkey') and isinstance(ssk.vkey, musig.PublicKey)
        assert hasattr(ssk, 'vkey_base') and isinstance(ssk.vkey_base, VerifyKey)
        assert ssk.skey == self.signing_keys[0]
        assert ssk.vkey_base == self.signing_keys[0].verify_key

    def test_SingleSigKey_from_bytes_raises_ValueError_or_TypeError_for_invalid_params(self):
        with self.assertRaises(ValueError) as err:
            musig.SingleSigKey.from_bytes(b'invalid bytes')
        assert str(err.exception) == 'bytes input must have length of 32'
        with self.assertRaises(TypeError):
            musig.SingleSigKey.from_bytes('not bytes')
        assert str(err.exception) == 'bytes input must have length of 32'

    def test_SingleSigKey_instances_serialize_and_deserialize_properly(self):
        ssk0 = musig.SingleSigKey({'skey': self.signing_keys[0]})
        bts1 = bytes(ssk0)
        str2 = str(ssk0)
        js = dumps(ssk0)
        ssk1 = musig.SingleSigKey.from_bytes(bts1)
        ssk2 = musig.SingleSigKey.from_str(str2)
        ssk3 = musig.SingleSigKey(loads(js))

        assert type(bts1) is bytes and len(bts1) == 32
        assert type(str2) is str and len(str2) == 64
        assert type(js) is str

        assert ssk0 == ssk1
        assert ssk0 == ssk2
        assert ssk0 == ssk3

    def test_SingleSigKey_sign_message_method_returns_Signature(self):
        ssk = musig.SingleSigKey({'skey': self.signing_keys[0]})
        sig = ssk.sign_message(b'hello world')
        assert isinstance(sig, musig.Signature)

    def test_SingleSigKey_signatures_are_verified_by_relevant_PublicKey(self):
        ssk = musig.SingleSigKey({'skey': self.signing_keys[0]})
        sig = ssk.sign_message(b'hello world')
        pubkey = ssk.vkey.public()
        assert pubkey.verify(sig)


if __name__ == '__main__':
    unittest.main()
