from context import musig
from nacl.signing import SigningKey
import unittest


class TestMuSigHelpers(unittest.TestCase):
    """Test suite for the helper functions used by the various classes."""
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

    def setUp(self):
        pass

    def test_clamp_scalar_raises_ValueError_when_given_invalid_arg(self):
        with self.assertRaises(ValueError):
            musig.clamp_scalar(None)

    def test_clamp_scalar_returns_bytes_different_from_unclamped_arg(self):
        original = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
        clamped = musig.clamp_scalar(original)
        assert type(clamped) is bytes
        assert original != clamped

    def test_aggregate_points_raises_TypeError_for_invalid_args(self):
        with self.assertRaises(TypeError):
            musig.aggregate_points(['123', None])

    def test_aggregate_points_raises_ValueError_for_invalid_points(self):
        with self.assertRaises(ValueError):
            musig.aggregate_points([bytes.fromhex(''.join(['ff' for i in range(32)]))])

        with self.assertRaises(ValueError):
            musig.aggregate_points([bytes.fromhex(''.join(['00' for i in range(32)]))])

    def test_aggregate_points_returns_bytes_when_given_VerifyKey_args(self):
        points = self.verify_keys
        assert type(musig.aggregate_points(points)) is bytes

    def test_H_big_returns_bytes(self):
        assert type(musig.H_big(b'asd', b'sdsd')) is bytes

    def test_H_small_returns_bytes(self):
        assert type(musig.H_small(b'asd', b'dfdfd')) is bytes

    def test_derive_key_from_seed_returns_bytes(self):
        assert type(musig.derive_key_from_seed(b'sds')) is bytes

    def test_derive_challenge_returns_bytes(self):
        L = b'123'
        X_i = b'321'
        X = b'213'
        R = b'dsd'
        M = b'dsds'
        assert type(musig.derive_challenge(L, X_i, X, R, M)) is bytes

    def test_H_agg_returns_clamped_bytes(self):
        output = musig.H_agg(b'asds', b'adsd')
        assert type(output) is bytes
        assert musig.clamp_scalar(output) == output

    def test_H_sig_returns_clamped_bytes(self):
        output = musig.H_sig(b'adssd', b'asdsd', b'asdsdsd')
        assert type(output) is bytes
        assert musig.clamp_scalar(output) == output

    def test_xor_returns_bytes_and_xors_arguments(self):
        assert type(musig.xor(b'123', b'123')) is bytes
        assert musig.xor(b'1', b'1')[0] == 0

    def test_bytes_are_same_returns_bool_and_is_accurate(self):
        assert type(musig.bytes_are_same(b'1', b'1')) is bool
        assert musig.bytes_are_same(b'1', b'1')
        assert not musig.bytes_are_same(b'1', b'2')


if __name__ == '__main__':
    unittest.main()
