from context import musig
from json import dumps, loads
from musig import Nonce, NonceCommitment
import inspect
import unittest


class TestMuSigNonceCommitment(unittest.TestCase):
    """Test suite for NonceCommitment."""
    def test_NonceCommitment_is_a_class(self):
        assert inspect.isclass(NonceCommitment)

    def test_NonceCommitment_init_raises_ValueError_with_empty_or_invalid_params(self):
        with self.assertRaises(ValueError):
            NonceCommitment()
        with self.assertRaises(ValueError):
            NonceCommitment('invalid input')
        with self.assertRaises(ValueError):
            NonceCommitment(['invalid input'])

    def test_NonceCommitment_instance_has_HR_when_initialized_with_Nonce(self):
        n = Nonce()
        nc = NonceCommitment(n)
        assert hasattr(nc, 'HR')
        assert type(nc.HR) is bytes
        assert type(nc['HR']) is str

    def test_NonceCommitment_instance_is_valid_for_raises_ValueError_when_given_nonNonce(self):
        n = Nonce()
        nc = NonceCommitment(n)
        with self.assertRaises(ValueError):
            nc.is_valid_for('not a nonce')

    def test_NonceCommitment_instance_is_valid_for_method_returns_correct_values(self):
        n = Nonce()
        n2 = Nonce()
        nc = NonceCommitment(n)
        assert nc.is_valid_for(n)
        assert not nc.is_valid_for(n2)

    def test_NonceCommitment_deserialize_raises_ValueError_for_invalid_serialization(self):
        with self.assertRaises(ValueError):
            NonceCommitment.deserialize('invalid str')
        with self.assertRaises(ValueError):
            NonceCommitment.deserialize('invalid.str')
        with self.assertRaises(ValueError):
            NonceCommitment.deserialize({'not-HR':'asd'})

    def test_NonceCommitment_instances_serialize_and_deserialize_properly(self):
        nc0 = NonceCommitment(Nonce())
        str1 = nc0.__str__()
        str2 = nc0.__repr__()
        str3 = nc0.serialize()
        js = dumps(nc0)
        bts = bytes(nc0)
        nc1 = NonceCommitment(str1)
        nc2 = NonceCommitment(str2)
        nc3 = NonceCommitment(str3)
        nc4 = NonceCommitment('json.' + js)
        nc5 = NonceCommitment(loads(js))
        nc6 = NonceCommitment(bts)

        assert type(str1) is str and str1[:2] == '16'
        assert type(str2) is str and str2[:2] == '64'
        assert type(js) is str

        assert nc0 == nc1
        assert nc1 == nc2
        assert nc2 == nc3
        assert nc3 == nc4
        assert nc4 == nc5
        assert nc5 == nc6

    def test_NonceCommitment_instances_can_be_members_of_sets(self):
        nc0 = NonceCommitment(Nonce())
        nc1 = nc0.copy()
        nc2 = NonceCommitment(Nonce())

        ncs = set([nc0, nc1, nc2])
        assert len(ncs) == 2


if __name__ == '__main__':
    unittest.main()
