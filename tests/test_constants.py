from context import musig
import unittest


class TestMuSigConstants(unittest.TestCase):
    """Test suite for the constants used by the various classes."""

    def test_musig_has_MAX_WAIT_TIME_FOR_COMMITMENTS(self):
        assert hasattr(musig, 'MAX_WAIT_TIME_FOR_COMMITMENTS')
        assert type(musig.MAX_WAIT_TIME_FOR_COMMITMENTS) is int

    def test_musig_has_MAX_WAIT_TIME_FOR_PUBLIC_NONCES(self):
        assert hasattr(musig, 'MAX_WAIT_TIME_FOR_PUBLIC_NONCES')
        assert type(musig.MAX_WAIT_TIME_FOR_PUBLIC_NONCES) is int

    def test_musig_has_MAX_WAIT_TIME_FOR_PARTIAL_SIGS(self):
        assert hasattr(musig, 'MAX_WAIT_TIME_FOR_PARTIAL_SIGS')
        assert type(musig.MAX_WAIT_TIME_FOR_PARTIAL_SIGS) is int


if __name__ == '__main__':
    unittest.main()
