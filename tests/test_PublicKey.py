from context import musig
from json import dumps, loads
from nacl.signing import SigningKey, VerifyKey
import inspect
import unittest


class TestMuSigPublicKey(unittest.TestCase):
    """Test suite for PublicKey."""
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

    def test_PublicKey_is_a_class(self):
        assert inspect.isclass(musig.PublicKey)

    def test_PublicKey_init_raises_ValueError_without_proper_arg(self):
        with self.assertRaises(ValueError) as err:
            musig.PublicKey()
        assert str(err.exception) == 'cannot instantiate empty PublicKey'

        with self.assertRaises(TypeError) as err:
            musig.PublicKey((1,2))
        assert str(err.exception) == 'input data must be dict'

    def test_PublicKey_instances_have_key_set_encodings_when_created_from_keys(self):
        aggkey = musig.PublicKey.create(self.verify_keys)
        assert hasattr(aggkey, 'L')
        assert type(aggkey.L) is bytes

    def test_PublicKey_instances_have_gvkey_when_created_from_keys(self):
        aggkey = musig.PublicKey.create(self.verify_keys)
        assert hasattr(aggkey, 'gvkey')
        assert type(aggkey.gvkey) is bytes

    def test_PublicKey_instances_have_vkeys_when_created_from_keys(self):
        aggkey = musig.PublicKey.create(self.verify_keys)
        assert hasattr(aggkey, 'vkeys')
        assert type(aggkey.vkeys) is tuple
        for vk in aggkey.vkeys:
            assert isinstance(vk, VerifyKey)

    def test_PublicKey_instances_have_correct_key_set_encodings(self):
        aggkey1 = musig.PublicKey.create(self.verify_keys[:1])
        aggkey2 = musig.PublicKey.create(self.verify_keys[:2])
        aggkey3 = musig.PublicKey.create(self.verify_keys[:3])

        expected1 = musig.H_small(*[vk.__bytes__() for vk in self.verify_keys[:1]])
        expected2 = musig.H_small(*sorted([vk.__bytes__() for vk in self.verify_keys[:2]]))
        expected3 = musig.H_small(*sorted([vk.__bytes__() for vk in self.verify_keys[:3]]))

        assert aggkey1.L == expected1
        assert aggkey2.L == expected2
        assert aggkey3.L == expected3

    def test_PublicKey_instances_have_correct_aggregate_keys(self):
        aggkey1 = musig.PublicKey.create(self.verify_keys[:1])
        aggkey2 = musig.PublicKey.create(self.verify_keys[:2])
        aggkey3 = musig.PublicKey.create(self.verify_keys[:3])

        expected1 = '03bbdee1f53985e5889bf704a1abe1b313ee302a1630af5fe6cc9f350c94b7e6'
        expected2 = '4c42a4d7403669d652139aa43620ea43b65f8405b10ba34de90a641b86802747'
        expected3 = 'eecb56e70d2405a849aa5e55b6e2f96aac2957dba72f8c289994c842e33ec477'

        assert aggkey1.gvkey.hex() == expected1
        assert aggkey2.gvkey.hex() == expected2
        assert aggkey3.gvkey.hex() == expected3

    def test_PublicKey_from_bytes_raises_ValueError_or_TypeError_when_given_invalid_serialization(self):
        with self.assertRaises(TypeError) as err:
            musig.PublicKey.from_bytes('not bytes')
        assert str(err.exception) == 'cannot call from_bytes with non-bytes param'
        with self.assertRaises(ValueError) as err:
            musig.PublicKey.from_bytes(b'incorrect length')
        assert str(err.exception) == 'byte length must be a multiple of 32'

    def test_PublicKey_from_str_works_when_given_hex_str_with_gvkey(self):
        aggkey = musig.PublicKey.from_str('cc607fdd093041cdd29408d3a26098490b6eba370e00b5808e8c344f47897251')
        assert type(aggkey) is musig.PublicKey
        assert aggkey.gvkey.hex() == 'cc607fdd093041cdd29408d3a26098490b6eba370e00b5808e8c344f47897251'

    def test_PublicKey_from_str_works_when_given_hex_str_of_vkeys(self):
        vkeys = [
            '3139a8eacf6b00b9d420831381a75a73cbef3ffbdaa7796861a034a479844071',
            'da9fe36cb2845734cf1b4c3487340b4f13c519310434893cfa84e275a10f5cac',
            'fc01e0f7c9222529a8f1d5ae3e973745eb163f521e6e347e8f1b14fe9fc15692'
        ]
        aggkey = musig.PublicKey.from_str(''.join(vkeys))
        assert type(aggkey) is musig.PublicKey
        assert aggkey.gvkey.hex() == 'eecb56e70d2405a849aa5e55b6e2f96aac2957dba72f8c289994c842e33ec477'

    def test_PublicKey_public_method_returns_instance_with_only_gvkey(self):
        aggkey = musig.PublicKey.create(self.verify_keys)
        pubkey = aggkey.public()
        assert len(aggkey.vkeys) == 3
        assert len(pubkey.vkeys) == 0
        assert type(pubkey.gvkey) is bytes
        assert pubkey.gvkey == aggkey.gvkey
        assert len(pubkey.vkeys) == 0
        assert pubkey.L is None

    def test_PublicKey_instance_serialize_and_deserialize_properly(self):
        aggkey0 = musig.PublicKey.create(self.verify_keys)
        aggkey00 = aggkey0.public()
        bts1 = bytes(aggkey0)
        bts11 = bytes(aggkey00)
        str2 = str(aggkey0)
        str22 = str(aggkey00)
        js3 = dumps(aggkey0)
        js33 = dumps(aggkey00)

        aggkey1 = musig.PublicKey.from_bytes(bts1)
        aggkey11 = musig.PublicKey.from_bytes(bts11)
        aggkey2 = musig.PublicKey.from_str(str2)
        aggkey22 = musig.PublicKey.from_str(str22)
        aggkey3 = musig.PublicKey(loads(js3))
        aggkey33 = musig.PublicKey(loads(js33))

        assert aggkey0 == aggkey1
        assert aggkey0 == aggkey2
        assert aggkey0 == aggkey3

        assert aggkey00 == aggkey11
        assert aggkey00 == aggkey22
        assert aggkey00 == aggkey33

        assert aggkey0.L is not None
        assert aggkey00.L is None
        assert len(aggkey0.vkeys) > 0
        assert len(aggkey00.vkeys) == 0

    def test_PublicKey_instances_have_verify_method(self):
        aggkey = musig.PublicKey.create(self.verify_keys)
        assert hasattr(aggkey, 'verify')
        assert inspect.ismethod(aggkey.verify)


if __name__ == '__main__':
    unittest.main()
