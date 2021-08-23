from context import musig
from json import dumps, loads
import inspect
import nacl.bindings
import unittest


class TestMuSigNonce(unittest.TestCase):
    """Test suite for Nonce."""
    def test_Nonce_is_a_class(self):
        assert inspect.isclass(musig.Nonce)

    def test_Nonce_instance_has_r_and_R_when_initialized_with_empty_params(self):
        nonce = musig.Nonce()
        assert hasattr(nonce, 'r')
        assert type(nonce.r) is bytes
        assert len(nonce.r) == nacl.bindings.crypto_core_ed25519_SCALARBYTES
        assert hasattr(nonce, 'R')
        assert type(nonce.R) is bytes
        assert nacl.bindings.crypto_core_ed25519_is_valid_point(nonce.R)
        assert 'r' in nonce
        assert type(nonce['r']) is str
        assert 'R' in nonce
        assert type(nonce['R']) is str

    def test_Nonce_instance_cannot_set_key_other_than_r_and_R(self):
        nonce = musig.Nonce()
        nonce['arbitrary_key'] = 'arbitrary value'
        assert 'arbitrary_key' not in nonce
        assert not hasattr(nonce, 'arbitrary_key')

    def test_Nonce_instances_add_together_and_return_point(self):
        n1 = musig.Nonce()
        n2 = musig.Nonce()
        n3 = n1 + n2
        assert n3 != n1
        assert n3 != n2
        assert isinstance(n3, musig.Nonce)
        assert hasattr(n3, 'R')
        assert nacl.bindings.crypto_core_ed25519_is_valid_point(n3.R)
        assert n3.r == None

    def test_Nonce_instance_public_method_returns_Nonce_without_private_value(self):
        n0 = musig.Nonce()
        assert hasattr(n0, 'public')
        assert inspect.ismethod(n0.public)
        n1 = n0.public()
        assert isinstance(n1, musig.Nonce)
        assert n1.r is None
        assert type(n1.R) is bytes

    def test_Nonce_from_bytes_raises_TypeError_or_ValueError_when_given_invalid_data(self):
        with self.assertRaises(TypeError) as err:
            musig.Nonce.from_bytes('not bytes')
        assert str(err.exception) == 'cannot call from_bytes with non-bytes param'
        with self.assertRaises(ValueError) as err:
            musig.Nonce.from_bytes(b'not len 32')
        assert str(err.exception) == 'byte length must be 32 or 33'

    def test_Nonce_instances_serialize_and_deserialize_properly(self):
        n0 = musig.Nonce()
        bts = bytes(n0)
        str1 = str(n0)
        js = dumps(n0)
        n1 = musig.Nonce.from_bytes(bts)
        n2 = musig.Nonce.from_str(str1)
        n3 = musig.Nonce(loads(js))

        assert type(bts) is bytes
        assert type(str1) is str
        assert type(js) is str
        assert n0.r == n1.r and n0.R == n1.R
        assert n0.r == n2.r and n0.R == n2.R
        assert n0.r == n3.r and n0.R == n3.R

    def test_Nonce_instances_with_only_public_value_serialize_and_deserialize_properly(self):
        n0 = musig.Nonce().public()
        bts1 = bytes(n0)
        str1 = str(n0)
        js0 = dumps(n0)
        n1 = musig.Nonce.from_bytes(bts1)
        n2 = musig.Nonce.from_str(str1)
        n3 = musig.Nonce(loads(js0))
        assert n1.r is None and n0.R == n1.R
        assert n2.r is None and n0.R == n2.R
        assert n3.r is None and n0.R == n3.R

    def test_Nonce_instances_can_be_members_of_sets(self):
        n0 = musig.Nonce()
        n1 = n0.copy()
        n2 = musig.Nonce()
        ns = list(set([n0, n1, n2]))
        assert n0 == n1
        assert hash(n0) == hash(n1)
        assert len(ns) == 2


if __name__ == '__main__':
    unittest.main()
