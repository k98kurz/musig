from context import musig
from json import dumps, loads
import inspect
import unittest


class TestMuSigNonceCommitment(unittest.TestCase):
    """Test suite for NonceCommitment."""
    def test_NonceCommitment_is_a_class(self):
        assert inspect.isclass(musig.NonceCommitment)

    def test_NonceCommitment_init_raises_ValueErroror_TypeError_with_empty_or_invalid_params(self):
        with self.assertRaises(TypeError):
            musig.NonceCommitment()
        with self.assertRaises(TypeError):
            musig.NonceCommitment('invalid input')
        with self.assertRaises(TypeError):
            musig.NonceCommitment(['invalid input'])

    def test_NonceCommitment_instance_has_HR_when_initialized_with_Nonce(self):
        n = musig.Nonce()
        nc = musig.NonceCommitment.create(n)
        assert hasattr(nc, 'HR')
        assert type(nc.HR) is bytes
        assert type(nc['HR']) is str

    def test_NonceCommitment_instance_is_valid_for_raises_ValueError_when_given_nonNonce(self):
        n = musig.Nonce()
        nc = musig.NonceCommitment.create(n)
        with self.assertRaises(ValueError):
            nc.is_valid_for('not a nonce')

    def test_NonceCommitment_instance_is_valid_for_method_returns_correct_values(self):
        n = musig.Nonce()
        n2 = musig.Nonce()
        nc = musig.NonceCommitment.create(n)
        assert nc.is_valid_for(n)
        assert not nc.is_valid_for(n2)

    def test_NonceCommitment_from_bytes_raises_ValueError_or_TypeError_for_invalid_serialization(self):
        with self.assertRaises(TypeError) as err:
            musig.NonceCommitment.from_bytes('not bytes')
        assert str(err.exception) == 'data must be bytes of len 32'
        with self.assertRaises(ValueError) as err:
            musig.NonceCommitment.from_bytes(b'not 32 len')
        assert str(err.exception) == 'data must be bytes of len 32'

    def test_NonceCommitment_instances_serialize_and_deserialize_properly(self):
        nc0 = musig.NonceCommitment.create(musig.Nonce())
        bts = bytes(nc0)
        str0 = str(nc0)
        js = dumps(nc0)
        nc1 = musig.NonceCommitment.from_bytes(bts)
        nc2 = musig.NonceCommitment.from_str(str0)
        nc3 = musig.NonceCommitment(loads(js))

        assert type(bts) is bytes
        assert type(str0) is str
        assert type(js) is str

        assert nc0 == nc1
        assert nc1 == nc2
        assert nc2 == nc3
        assert len(nc3.HR) == 32

    def test_NonceCommitment_instances_can_be_members_of_sets(self):
        nc0 = musig.NonceCommitment.create(musig.Nonce())
        nc1 = nc0.copy()
        nc2 = musig.NonceCommitment.create(musig.Nonce())

        ncs = list(set([nc0, nc1, nc2]))
        assert len(ncs) == 2


if __name__ == '__main__':
    unittest.main()
