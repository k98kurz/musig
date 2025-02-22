from musig.constants import (
    MAX_WAIT_TIME_FOR_COMMITMENTS,
    MAX_WAIT_TIME_FOR_PUBLIC_NONCES,
    MAX_WAIT_TIME_FOR_PARTIAL_SIGS,
)
from musig.helpers import (
    clamp_scalar, aggregate_points, H_big, H_small, derive_key_from_seed,
    derive_challenge, H_agg, H_sig, xor, bytes_are_same
)
from musig.nonce import Nonce
from musig.noncecommitment import NonceCommitment
from musig.partialsignature import PartialSignature
from musig.publickey import PublicKey
from musig.signature import Signature
# the below imports must be in this order due to dependency coupling
from musig.protocol import ProtocolState, ProtocolError, ProtocolMessage
from musig.singlesigkey import SingleSigKey
from musig.signingsession import SigningSession

__version__ = '0.1.0'

def version() -> str:
    """Return the version of the package."""
    return __version__
