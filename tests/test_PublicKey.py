from context import musig
from json import dumps, loads
from nacl.signing import SigningKey
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
        with self.assertRaises(ValueError):
            musig.PublicKey()

        with self.assertRaises(ValueError):
            musig.PublicKey((1,2))

    def test_PublicKey_instances_have_key_set_encodings_when_created_from_keys(self):
        aggkey = musig.PublicKey(self.verify_keys)
        assert hasattr(aggkey, 'L')
        assert type(aggkey.L) is bytes

    def test_PublicKey_instances_have_gvkey_when_created_from_keys(self):
        aggkey = musig.PublicKey(self.verify_keys)
        assert hasattr(aggkey, 'gvkey')
        assert type(aggkey.gvkey) is bytes

    def test_PublicKey_instances_have_correct_key_set_encodings(self):
        aggkey1 = musig.PublicKey(self.verify_keys[:1])
        aggkey2 = musig.PublicKey(self.verify_keys[:2])
        aggkey3 = musig.PublicKey(self.verify_keys[:3])

        expected1 = musig.H_small(*[vk.__bytes__() for vk in self.verify_keys[:1]])
        expected2 = musig.H_small(*sorted([vk.__bytes__() for vk in self.verify_keys[:2]]))
        expected3 = musig.H_small(*sorted([vk.__bytes__() for vk in self.verify_keys[:3]]))

        assert aggkey1.L == expected1
        assert aggkey2.L == expected2
        assert aggkey3.L == expected3

    def test_PublicKey_instances_have_correct_aggregate_keys(self):
        aggkey1 = musig.PublicKey(self.verify_keys[:1])
        aggkey2 = musig.PublicKey(self.verify_keys[:2])
        aggkey3 = musig.PublicKey(self.verify_keys[:3])

        expected1 = '03bbdee1f53985e5889bf704a1abe1b313ee302a1630af5fe6cc9f350c94b7e6'
        expected2 = '4c42a4d7403669d652139aa43620ea43b65f8405b10ba34de90a641b86802747'
        expected3 = 'eecb56e70d2405a849aa5e55b6e2f96aac2957dba72f8c289994c842e33ec477'

        assert aggkey1.gvkey.hex() == expected1
        assert aggkey2.gvkey.hex() == expected2
        assert aggkey3.gvkey.hex() == expected3

    def test_PublicKey_deserialize_raises_ValueError_when_given_invalid_serialization(self):
        with self.assertRaises(ValueError):
            musig.PublicKey.deserialize('invalid str')
        with self.assertRaises(ValueError):
            musig.PublicKey.deserialize('invalid.str')

    def test_PublicKey_init_works_when_given_hex_str_with_gvkey(self):
        aggkey = musig.PublicKey('16.cc607fdd093041cdd29408d3a26098490b6eba370e00b5808e8c344f47897251')
        assert type(aggkey) is musig.PublicKey
        assert aggkey.gvkey.hex() == 'cc607fdd093041cdd29408d3a26098490b6eba370e00b5808e8c344f47897251'

    def test_PublicKey_init_works_when_given_b64_str_with_gvkey(self):
        aggkey = musig.PublicKey('64.zGB/3QkwQc3SlAjTomCYSQtuujcOALWAjow0T0eJclE=')
        assert type(aggkey) is musig.PublicKey
        assert aggkey.gvkey.hex() == 'cc607fdd093041cdd29408d3a26098490b6eba370e00b5808e8c344f47897251'

    def test_PublicKey_init_works_when_given_hex_str_with_vkeys(self):
        vkeys = [
            '3139a8eacf6b00b9d420831381a75a73cbef3ffbdaa7796861a034a479844071',
            'da9fe36cb2845734cf1b4c3487340b4f13c519310434893cfa84e275a10f5cac',
            'fc01e0f7c9222529a8f1d5ae3e973745eb163f521e6e347e8f1b14fe9fc15692'
        ]
        aggkey = musig.PublicKey('16i.' + '.'.join(vkeys))
        assert type(aggkey) is musig.PublicKey
        assert aggkey.gvkey.hex() == 'eecb56e70d2405a849aa5e55b6e2f96aac2957dba72f8c289994c842e33ec477'

    def test_PublicKey_init_works_when_given_b64_str_with_vkeys(self):
        vkeys = [
            'MTmo6s9rALnUIIMTgadac8vvP/vap3loYaA0pHmEQHE=',
            '2p/jbLKEVzTPG0w0hzQLTxPFGTEENIk8+oTidaEPXKw=',
            '/AHg98kiJSmo8dWuPpc3ResWP1IebjR+jxsU/p/BVpI='
        ]
        aggkey = musig.PublicKey('64i.' + '.'.join(vkeys))
        assert type(aggkey) is musig.PublicKey
        assert aggkey.gvkey.hex() == 'eecb56e70d2405a849aa5e55b6e2f96aac2957dba72f8c289994c842e33ec477'

    def test_PublicKey_instance_serialize_method_returns_str(self):
        aggkey = musig.PublicKey(self.verify_keys)
        assert hasattr(aggkey, 'serialize')
        assert inspect.ismethod(aggkey.serialize)
        assert type(aggkey.serialize()) is str

    def test_PublicKey_instance_can_be_serialized_with_json(self):
        aggkey1 = musig.PublicKey(self.verify_keys)
        serialized = dumps(aggkey1)
        deserialized = loads(serialized)
        aggkey2 = musig.PublicKey(deserialized)

        assert hasattr(aggkey2, 'L') and 'L' in aggkey2
        assert aggkey1['L'] == aggkey2['L']
        assert hasattr(aggkey2, 'gvkey') and 'gvkey' in aggkey2
        assert aggkey1['gvkey'] == aggkey2['gvkey']
        assert hasattr(aggkey2, 'vkeys') and 'vkeys' in aggkey2
        assert aggkey1['vkeys'] == aggkey2['vkeys']

    def test_PublicKey_instances_have_verify_method(self):
        aggkey = musig.PublicKey(self.verify_keys)
        assert hasattr(aggkey, 'verify')
        assert inspect.ismethod(aggkey.verify)


if __name__ == '__main__':
    unittest.main()
