"""A collection of helper functions that are used by many classes. Not all
    calls to nacl.bindings functions are abstracted into helpers, but many are.
    Each function has a short docblock explaining its purpose.
"""


from hashlib import new
from nacl.signing import SigningKey, VerifyKey
import nacl.bindings


def clamp_scalar(scalar: bytes|SigningKey, from_private_key: bool = False) -> bytes:
    """Make a clamped scalar."""
    if type(scalar) is bytes and len(scalar) >= 32:
        x_i = bytearray(scalar[:32])
    elif type(scalar) is SigningKey:
        x_i = bytearray(new('sha512', bytes(scalar)).digest()[:32])
        from_private_key = True
    else:
        raise ValueError('not a SigningKey and not 32+ bytes scalar')

    if from_private_key:
        # set bits 0, 1, and 2 to 0
        # nb: lsb is right-indexed
        x_i[0] &= 0b11111000
        # set bit 254 to 1
        x_i[31] |= 0b01000000

    # set bit 255 to 0
    x_i[31] &= 0b01111111

    return bytes(x_i)

def aggregate_points(points: list[bytes|VerifyKey]) -> bytes:
    """Aggregate points on the Ed25519 curve."""
    # type checking inputs
    for pt in points:
        if type(pt) is not bytes and type(pt) is not VerifyKey:
            raise TypeError('each point must be bytes or VerifyKey')

    # normalize points to bytes
    points = [pt if type(pt) is bytes else bytes(pt) for pt in points]

    # raise an error for invalid points
    for pt in points:
        if not nacl.bindings.crypto_core_ed25519_is_valid_point(pt):
            raise ValueError('each point must be a valid ed25519 point')

    # compute the sum
    sum = points[0]
    for i in range(1, len(points)):
        sum = nacl.bindings.crypto_core_ed25519_add(sum, points[i])

    return sum

def H_big(*parts: bytes) -> bytes:
    """The big, 64-byte hash function."""
    return new('sha512', b''.join(parts)).digest()

def H_small(*parts: bytes) -> bytes:
    """The small, 32-byte hash function."""
    return nacl.bindings.crypto_core_ed25519_scalar_reduce(H_big(*parts))

def derive_key_from_seed(seed: bytes) -> bytes:
    """Derive the scalar used for signing from a seed."""
    return clamp_scalar(H_big(seed)[:32], True)

def derive_challenge(L: bytes, X_i: bytes, X: bytes, R: bytes, M: bytes) -> bytes:
    """Derive the challenge used for making a partial signature."""
    a_i = H_agg(L, X_i)
    c = H_sig(R, X, M)
    return clamp_scalar(nacl.bindings.crypto_core_ed25519_scalar_mul(a_i, c))

def H_agg(L: bytes, X_i: bytes) -> bytes:
    """The hash used for aggregating keys."""
    return clamp_scalar(H_small(L, X_i))

def H_sig(R: bytes, X: bytes, M: bytes) -> bytes:
    """The hash used to derive the challenge used in signing and verifying."""
    return clamp_scalar(H_small(R, X, M))

def xor(b1: bytes, b2: bytes) -> bytes:
    """XOR two equal-length byte strings together."""
    b3 = bytearray()
    for i in range(len(b1)):
        b3.append(b1[i] ^ b2[i])

    return bytes(b3)

def bytes_are_same(b1: bytes, b2: bytes) -> bool:
    """Timing-attack safe bytes comparison."""
    return len(b1) == len(b2) and int.from_bytes(xor(b1, b2), 'little') == 0
