from context import musig
from json import dumps, loads
from musig.Nonce import Nonce
from nacl.signing import SigningKey
import inspect
import nacl.bindings
import unittest


class TestMuSigNonce(unittest.TestCase):
    """Test suite for Nonce."""
    def test_Nonce_is_a_class(self):
        assert inspect.isclass(Nonce)

    def test_Nonce_instance_has_r_and_R_when_initialized_with_empty_params(self):
        nonce = Nonce()
        assert hasattr(nonce, 'r')
        assert type(nonce.r) is bytes
        assert len(nonce.r) == nacl.bindings.crypto_core_ed25519_SCALARBYTES
        assert hasattr(nonce, 'R')
        assert type(nonce.R) is bytes
        assert nacl.bindings.crypto_core_ed25519_is_valid_point(nonce.R)

    def test_Nonce_instances_add_together_and_return_point(self):
        n1 = Nonce()
        n2 = Nonce()
        n3 = n1 + n2
        assert n3 != n1
        assert n3 != n2
        assert isinstance(n3, Nonce)
        assert hasattr(n3, 'R')
        assert nacl.bindings.crypto_core_ed25519_is_valid_point(n3.R)
        assert n3.r == None

    def test_Nonce_instance_public_method_returns_Nonce_without_private_value(self):
        n0 = Nonce()
        assert hasattr(n0, 'public')
        assert inspect.ismethod(n0.public)
        n1 = n0.public()
        assert isinstance(n1, Nonce)
        assert n1.r is None
        assert type(n1.R) is bytes

    def test_Nonce_deserialize_raises_ValueError_when_given_invalid_str_data(self):
        with self.assertRaises(ValueError):
            Nonce.deserialize('invalid input')
        with self.assertRaises(ValueError):
            Nonce.deserialize('invalid.input')

    def test_Nonce_instances_serialize_and_deserialize_properly(self):
        n0 = Nonce()
        str1 = n0.__str__()
        str2 = n0.__repr__()
        str3 = n0.serialize()
        js = dumps(n0)
        str4 = 'json.'+js
        n1 = Nonce(str1)
        n2 = Nonce(str2)
        n3 = Nonce(str3)
        n4 = Nonce(str4)
        n5 = Nonce(loads(js))

        assert type(str1) is str and str1[:2] == '16'
        assert type(str2) is str and str2[:2] == '64'
        assert type(str3) is str and str3[:2] == '64'
        assert type(js) is str
        assert n0.r == n1.r and n0.R == n1.R
        assert n0.r == n2.r and n0.R == n2.R
        assert n0.r == n3.r and n0.R == n3.R
        assert n0.r == n4.r and n0.R == n4.R
        assert n0.r == n5.r and n0.R == n5.R

    def test_Nonce_instance_bytes_result_instantiates_public_value(self):
        n = Nonce()
        n2 = Nonce(bytes(n))
        assert n2.R == n.R
        assert n2.r is None

    def test_Nonce_instances_with_only_public_value_serialize_and_deserialize_properly(self):
        n0 = Nonce(Nonce().R)
        n00 = Nonce().public()
        str1 = n0.__str__()
        str11 = n00.__str__()
        str2 = n0.__repr__()
        str22 = n00.__repr__()
        js0 = dumps(n0)
        js00 = dumps(n00)
        str3 = 'json.'+js0
        str33 = 'json.'+js00
        n1 = Nonce(str1)
        n11 = Nonce(str11)
        n2 = Nonce(str2)
        n22 = Nonce(str22)
        n3 = Nonce(str3)
        n33 = Nonce(str33)
        n4 = Nonce(loads(js0))
        n44 = Nonce(loads(js00))
        assert n1.r is None and n0.R == n1.R
        assert n11.r is None and n00.R == n11.R
        assert n2.r is None and n0.R == n2.R
        assert n22.r is None and n00.R == n22.R
        assert n3.r is None and n0.R == n3.R
        assert n33.r is None and n00.R == n33.R
        assert n4.r is None and n0.R == n4.R
        assert n44.r is None and n00.R == n44.R

    def test_Nonce_instances_can_be_members_of_sets(self):
        n0 = Nonce()
        n1 = n0.copy()
        n2 = Nonce()

        ns = set([n0, n1, n2])
        assert len(ns) == 2


if __name__ == '__main__':
    unittest.main()
