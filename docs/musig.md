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
method bindings.

# Mathematics

The mathematics of MuSig are an extension of the mathematics of Schnorr
signatures on the Twisted Edwards curve 25519. The original paper (first link
in the references section below), is required reading. The main distinctions
between MuSig and naive multi-Schnorr are the key transformation step; the
exchange of nonce commitments before exchanging nonce points; and the partial
signatures using special deterministic challenges to account for the key
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

The first thing that occurs is the exchange of keys between participants. Once
all participants have all the public keys, the keys are ordered deterministically
and hashed into a key-set encoding, which is typically denoted `<L>` (the keyset
is denoted `L`). (In the code, I use `L` for the keyset encoding because angle
brackets cannot be used in variable names.)

Using the keyset encoding, each participant key can be transformed, and the
transformed keys can be summed together into the aggregate key (`X`):
```
a_i = H_agg(<L>, X_i)
X = sum(X_i ^ a_i)
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
R = sum(R_i)
x_i = derive_key_from_seed(skey)
X_i = g^x_i
a_i = H_agg(<L>, X_i)
c = H_sig(X, R, M)
s_i = a_i * c * x_i + r_i
```

The aggregate signature (`s`) is then computed by summing the partial sigs:
```
s = sum(s_i)
```

The full MuSig signature is then `s, R`. This can be verified with the aggregate
public key as follows:
```
c = H_sig(X, R, M)
assert g^s == R * X^c
```

Proof:
```
Given the functions:
    sum(x_i) = (x_0 + x_1 + ... + x_n)
    product(x_i) = (x_0 * x_1 * ... * x_n)

And the values:
    s = sum(s_i) = sum(a_i * c * x_i + r_i)
    X = product(X_i ^ a_i)
    R = product(g^r_i)

It follows that:
    g^s = R * X^c
    g^(sum(a_i * c * x_i + r_i)) = product(g^r_i) * product(X_i^a_i)^c
    g^(c * sum(a_i * x_i + r_i)) = product(g^r_i) * product((g^x_i)^a_i * c)
    g^c * g^sum(a_i * x_i + r_i) = product(g^r_i) * product(g^(x_i * a_i * c))
    g^c * g^sum(a_i * x_i + r_i) = product(g^r_i) * product(g^x_i * g^a_i * g^c)
    g^c * g^sum(a_i * x_i + r_i) = product(g^r_i) * g^c * product(g^x_i * g^a_i)
    g^c * g^sum(a_i * x_i + r_i) = g^c * product(g^r_i) * product(g^x_i * g^a_i)
    g^c * g^sum(a_i * x_i + r_i) = g^c * g^sum(r_i) * g^sum(x_i * a_i)
    g^c * g^sum(a_i * x_i + r_i) = g^c * g^sum(r_i + x_i * a_i)

QED


Supporting proofs:
    product(g^r_i) = g^sum(r_i):
        product(g^r_i)
        (g^r_0 * g^r+1 * ...)
        g^(r_0 + r_1 + ...)
        g^sum(r_i)

    product(g^x_i * g^a_i) = g^sum(x_i * a_i):
        product(g^x_i * g^a_i)
        (g^x_0 * g^a_0 * g^x_1 * g^a_1 * ...)
        g^(x_0 * a_0 * ...)
        g^sum(x_i * a_i)

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

# References

[Simple Schnorr Multi-Signatures with Applications to Bitcoin](https://eprint.iacr.org/2018/068.pdf)
[Insecure Shortcuts in MuSig](https://medium.com/blockstream/insecure-shortcuts-in-musig-2ad0d38a97da)
