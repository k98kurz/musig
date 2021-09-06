# Introduction

MuSig is a relatively new but well tested cryptographic protocol for multi-party
signatures, where the size of the signature and aggregate verification key have
constant size no matter the number of participants. MuSig is a n-of-n signature
scheme rather than an m-of-n scheme; to make an m-of-n scheme using MuSig, all
that is needed is to make concurrent sessions for each permutation of m of the
n participants and authorize all of the resultant aggregate public keys via
inclusion in a Merklized structure where the Merkle root becomes the m-of-n
public key. This is arguably more cumbersome than using a threshold signature
scheme, but the benefit is that the setup phase does not involve secret sharing,
splitting of keys between participants, etc; so long as participants can derive
their own ed25519 key pairs, they can create a MuSig aggregate key by simply
sharing their public keys.

This MuSig implementation uses pynacl for ed25519 signatures and mathematical
method bindings. One implementation detail which differs from the original
specification is that instead of the keyset being a multi-set, it is simply a
set (i.e. the same participant key cannot be added more than once). This change
should make uses of this module easier to test and debug.

# Mathematics

The mathematics of MuSig are an extension of the mathematics of Schnorr
signatures, in this case on the Twisted Edwards Curve 25519. The original paper
(first link in the references section below) is required reading. The main
distinctions between MuSig and naive multi-Schnorr are the key transformation
step; the exchange of nonce commitments before exchanging nonce points; and the
partial signatures using special deterministic challenges to account for the key
transformation.

Important notes:
- Scalar values are often "clamped" in ed25519:
    - In general, clamping is setting bit 255 to 0
    - For generating private keys, bits 0, 1, 2, and 255 are set to 0, and bit
    254 is set to 1.
    - I have omitted explanation of where to clamp for brevity.
- The hash algorithm used is sha512 in three forms:
    - `H_big` returns the full sha512 hash
    - `H_small` returns the sha512 hash reduced to a 32 byte ed25519 scalar
    - `H_sig` and `H_agg` clamp the output of `H_small`
- The MuSig paper uses the original Schnorr algebraic representation, but this
is not exactly accurate:
    - Multiplication of points is actually the group operation, which is the
    function `nacl.bindings.crypto_core_ed25519_add`.
    - Exponentiation of a point by a scalar is actually the group operation
    applied to the same point the scalar number of times, which is the function
    `nacl.bindings.crypto_scalarmult_ed25519_noclamp`.
    - These operations are done on a cyclic group, preserving the validity of
    the original algebraic formulation though the operations are different.
- Any var with `_i` is a member of a set and is unique for each participant,
whereas any var without `_i` is a singleton consistent for every participant. In
the proof section, `_i` is used to denote a set.
- The paper uses the nomenclature `H_sig(X, R, M)`, but this seems to be an
error. When `H_sig(R, X, M)` is used instead, the signatures become compatible
with the underlying pynacl ed25519 verification. See the third reference for the
original ed25519 specification which shows this to be the case (though they
used `A = aG` for the key pair nomenclature).

The first thing that occurs is the exchange of keys between participants. Once
all participants have all the public keys, the keys are ordered deterministically
and hashed into a key-set encoding, which is typically denoted `<L>` (the keyset
is denoted `L`). (In the code, I use `L` for the keyset encoding because angle
brackets cannot be used in variable names.)

Using the keyset encoding, each participant key can be transformed, and the
transformed keys can be summed together into the aggregate key (`X`):
```
a_i = H_agg(<L>, X_i)
X = product(X_i ^ a_i)
```

The next step is to exchange nonce commitments. A nonce is a clamped random
scalar (`r_i`) and an associated point (`R_i`) created by "exponentiation" of the
base/generator point (`g`), which is performed by the nacl function
`crypto_scalarmult_ed25519_base_noclamp`. A commitment (`HR`) is simply the
`H_small` of the nonce point. All participants generate their nonce and then
share their commitments. This is the only step that can be completed before a
message is decided upon, and it can be safely completed for any number of
concurrent sessions.

Once all nonce commitments have been exchanged, the participants can decide
upon a message to sign (`M`), and then exchange their nonce points (`R_i`). Each
nonce point must be valid for that participant's commitment, else the protocol
has been violated. The nonce points are summed together into an aggregate nonce
(`R`), and that is used to create the partial signatures for each participant
(`s_i`) are created from their key (`skey`) and a challenge (`c_i`):
```
R = product(R_i)
x_i = derive_key_from_seed(skey)
X_i = g^x_i
a_i = H_agg(<L>, X_i)
c = H_sig(R, X, M)
s_i = a_i * c * x_i + r_i
```

The aggregate signature (`s`) is then computed by summing the partial sigs:
```
s = sum(s_i)
```

The full MuSig signature is then `s, R`. This can be verified with the aggregate
public key as follows:
```
c = H_sig(R, X, M)
assert g^s == R * X^c
```

Proof:
```
Given the functions:
    sum(x_i) = (x_1 + ... + x_n)
    product(x_i) = (x_1 * ... * x_n)

And the values:
    s = sum(s_i) = sum(a_i * c * x_i + r_i)
    X = product(X_i^a_i)
    R = product(g^r_i)

It follows that:
    g^s = R * X^c
    g^(sum(a_i * c * x_i + r_i)) = product(g^r_i) * product(X_i^(a_i * c))
    g^sum(a_i * c * x_i) * g^sum(r_i) = product(g^r_i) * product(X_i^(a_i * c))
    g^(c * sum(a_i * x_i)) * g^sum(r_i) = product(g^r_i) * product(g^(x_i * a_i * c))
    g^(c * sum(a_i * x_i)) * g^sum(r_i) = g^sum(r_i) * g^sum(x_i * a_i * c)
    g^(c * sum(a_i * x_i)) * g^sum(r_i) = g^(c * sum(x_i * a_i)) * g^sum(r_i)

QED


Supporting proofs:
    product(g^r_i) = g^sum(r_i):
        product(g^r_i)
        (g^r_0 * g^r_1 * ...)
        g^(r_0 + r_1 + ...)
        g^sum(r_i)

    g^sum(r_i) * g^sum(x_i * a_i) = g^sum(r_i + x_i * a_i):
        g^sum(r_i) * g^sum(x_i * a_i)
        g^(r_0 + r_1 + ...) * g^(x_0 * a_0 + ...)
        g^(r_0 + ... + x_0 * a_0 + ...)
        g^sum(r_i + x_i * a_i)
```

# Safety Considerations for the Protocol

The nonce commitment round is crucial to avoid vulnerability to Wagner's
generalized birthday attack (see 2nd reference). Key transformation before
aggregation is necessary to mitigate rogue key attacks as outlined in the MuSig
paper. As an additional precautionary step, a session should abort if too much
time has passed between requesting and receiving all commitments, public nonces,
and partial signatures. In this module, these time constraints are defined in
`constants.py` and enforced by the `SigningSession` class.

To enable concurrent sessions for groups of participants with one aggregate key,
each session should have a unique id which should be included in all
transmissions between participants for that session. In this module, UUIDs are
used by the `SigningSession` class. It might be worthwhile for each participant
to initialize a session in a context in which multiple aggregate signatures are
expected to be required for an application.

For 1-of-1 MuSig, none of these concerns apply. In this module, there is a
`SingleSigKey` class that handles this simplified instantiation of MuSig.
Signatures and public keys will be indistinguishable no matter how many or few
participants contributed.

For classes included in this module, several have `public` methods that should
be called before sharing the values with other participants, e.g. `Nonce`.
Instances of `PublicKey` in particular must have `public` called before
serializing to bytes for distribution to a public network, else the participant
keys will be serialized instead, leaking private values. For 1-of-1 MuSig, if
the `PublicKey` is serialized to bytes without calling `public`, the underlying
ed25519 verify key will be serialized instead of the transformed aggregate key.

# Overview of Classes and Code

Each file includes its own documentation, so see the relevant file for more details.

## Constants
This module includes a set of constants that determine how much time is allowed
to pass between protocol steps without causing the session to abort (in seconds):
- `MAX_WAIT_TIME_FOR_COMMITMENTS`
- `MAX_WAIT_TIME_FOR_PUBLIC_NONCES`
- `MAX_WAIT_TIME_FOR_PARTIAL_SIGS`

## Helper Functions
This module includes a set of helper functions that abstract some of the calls
to `nacl.bindings` and whatnot:
- `clamp_scalar`: sets the relevant bits for a 32 byte scalar
- `aggregate_points`: sums points together
- `H_big`: returns sha512 hash of inputs
- `derive_key_from_seed`: derives the scalar used for signing
- `derive_challenge`: derives the challenge for making a partial signature
- `H_agg`: hash used for transforming keys before aggregation and deriving challenges
- `H_sig`: hash used for deriving challenges and verifying signatures
- `xor`: XORs two equal length bytes together; used by `bytes_are_same`
- `bytes_are_same`: timing-attack safe bytes comparison

## Abstract Classes
This module includes a set of abstract classes in `abstractclasses.py`:
- `ExtendedDict`:
    - Inherits from `dict` for json serializability
    - Implements custom `__setitem__`, `__str__`, `__hash__`, `__eq__`, and `from_str`
    - Requires implementation of `__bytes__` and `from_bytes`
- `AbstractNonce`:
    - Inherits from `ExtendedDict`
- `AbstractNonceCommitment`:
    - Inherits from `ExtendedDict`
- `AbstractPartialSignature`:
    - Inherits from `ExtendedDict`
- `AbstractPublicKey`:
    - Inherits from `ExtendedDict`
- `AbstractSignature`:
    - Inherits from `ExtendedDict`
- `AbstractSingleSigKey`:
    - Inherits from `ExtendedDict`
- `AbstractProtocolState`:
    - Uses `EnumMeta`
- `AbstractProtocolMessage`:
    - Inherits from `ExtendedDict`
- `AbstractSigningSession`:
    - Inherits from `ExtendedDict`

Each of the classes that inherits from `ExtendedDict` has abstract properties,
and only those properties that are defined can be set with `__setitem__` (e.g.
`thing[key] = value` only works if `hasattr(thing, key)`). Each requires a
definition of `__init__` for proper json deserialization and initialization.
Many include a `create` method for creation of new instances. All can be
serialized to and deserialized from bytes, str, and json.

## Classes
This module includes a set of classes in the following files:
- `nonce.py`:
    - `Nonce`: inherits from/implements `AbstractNonce`
- `noncecommitment.py`:
    - `NonceCommitment`: inherits from/implements `AbstractNonceCommitment`
- `partialsignature.py`:
    - `PartialSignature`: inherits from/implements `AbstractPartialSignature`
- `protocol.py`:
    - `ProtocolState`: an `Enum` meant to fulfill the role hinted by `AbstractProtocolState`
    - `ProtocolError`: inherits from `Exception`
    - `ProtocolMessage`: inherits from `AbstractProtocolMessage`
- `publickey.py`:
    - `PublicKey`: inherits from/implements `AbstractPublicKey`
- `signature.py`:
    - `Signature`: inherits from/implements `AbstractSignature`
- `signingsession.py`:
    - `SigningSession`: inherits from/implements `AbstractSigningSession`
- `singlesigkey.py`:
    - `SingleSigKey`: inherits from/implements `AbstractSingleSigKey`

## Tests
This module includes an extensive set of test suites with nearly 100% coverage.
These tests are found in the `tests/` dir and can be perused to gain a deeper
understanding of the behavior of the code. The tests can be run individually or
all at once. For every file of code, there is a corresponding test suite. Also,
there is a `context.py` file that allows the musig module to be imported into
the test files by changing the relative import path.

## Examples
There is a 2-of-2 example in the `examples/` directory. Similarly to the tests,
the path is changed to allow import from that directory. There is also a short
1-of-1 example in `readme.md`.

# References

- [Simple Schnorr Multi-Signatures with Applications to Bitcoin](https://eprint.iacr.org/2018/068.pdf)
- [Insecure Shortcuts in MuSig](https://medium.com/blockstream/insecure-shortcuts-in-musig-2ad0d38a97da)
- [High-speed high-security signatures](https://ed25519.cr.yp.to/ed25519-20110926.pdf)
    - Section 4 Signing messages, page 12: `S = (r + H(R, A, M)a) mod l`
