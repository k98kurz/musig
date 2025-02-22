# musig

## Classes

### `Nonce(AbstractNonce)`

A class that handles generating, serializing, and deserializing nonces.

#### Properties

- r: The private scalar value.
- R: The public point value.

#### Methods

##### `__init__(data: dict = None) -> None:`

Initialize the instance, either with supplied data or with new values. Call with
`data=None` to create a new Nonce. Call with `data={r:b64val}` or `{r:b64val,
R:b64val}` to restore a full Nonce. Call with `data={R:b64val}` to restore a
public Nonce.

##### `@classmethod from_bytes(data: bytes) -> Nonce:`

Deserializes output from __bytes__.

##### `copy() -> Nonce:`

Make a copy without serializing and deserializing.

##### `public() -> Nonce:`

Return a Nonce with only the public nonce point.

### `NonceCommitment(AbstractNonceCommitment)`

A class that handles generating, serializing, and deserializing nonce
commitments.

#### Properties

- HR: The nonce commitment bytes (hash of a nonce point).

#### Methods

##### `__init__(data: dict) -> None:`

Initialize with a dict.

##### `@classmethod create(nonce: AbstractNonce) -> NonceCommitment:`

Create a new instance by hashing the given nonce.

##### `copy() -> NonceCommitment:`

Make a copy without serializing and deserializing.

##### `is_valid_for(nonce: AbstractNonce) -> bool:`

Checks if the NonceCommitment is valid for a specific Nonce. Comparison is done
via xor'ing bytes to avoid timing attacks.

##### `@classmethod from_bytes(data: bytes) -> NonceCommitment:`

Deserializes output from __bytes__.

### `PartialSignature(AbstractPartialSignature)`

A class that handles creation, serialization, and deserialization of partial
signatures used to create MuSig aggregate signatures.

#### Properties

- c_i: The non-interactive challenge for the participant.
- s_i: The partial signature scalar.
- R: The aggregate nonce point.
- M: The message to be signed.

#### Methods

##### `__init__(data: dict) -> None:`

Initialize an instance with dict. At a minimum data should include s_i key with
base64-encoded value of 32 bytes; keys of c_i and R with base64-encoded value of
32 bytes each are optional; key of M with base64-encoded value of bytes is also
optional.

##### `@classmethod from_bytes(data: bytes) -> PartialSignature:`

Deserializes output from __bytes__.

##### `@classmethod create(skey: SigningKey, r_i: bytes, L: bytes, X: AbstractPublicKey, R: bytes, M: bytes) -> dict:`

Create a new instance using the SigningKey of the participant (skey), from which
the private key will be derived (bytes(skey) returns the seed); the private
nonce of the participant (r_i); the keyset encoding of the participants (L); the
aggregate public key (X); the aggregate public nonce point (R); and the message
(M).

##### `public() -> PartialSignature:`

Return a copy of the instance with only the public value (s_i).

### `PublicKey(AbstractPublicKey)`

A class that aggregates the public keys of participants of a Session and
verifies Signatures.

#### Properties

- L: The keyset encoding used for calculating partial signatures.
- gvkey: The bytes of the aggregate key (denoted X in the MuSig paper).
- vkeys: Tuple of untransformed participant VerifyKeys.

#### Methods

##### `__init__(data: dict = None) -> None:`

Initialize the instance using the given data. Initialize with `{'vkeys': list_of_vkeys}`
to create a PublicKey from participant keys. Initialize with `{'gvkey': bytes}`
to restore just enough to verify signatures.

##### `@classmethod from_bytes(data: bytes) -> PublicKey:`

Deserialize an instance from bytes.

##### `@classmethod create(vkeys: list[VerifyKey | bytes]) -> PublicKey:`

Create a new PublicKey from a list or tuple of participant VerifyKeys.

##### `public() -> PublicKey:`

Return a copy of the instance with only the public value (gvkey).

##### `verify(sig: AbstractSignature) -> bool:`

Verify a signature is valid for this PublicKey.

##### `@classmethod aggregate_public_keys(vkeys: list[VerifyKey | bytes], key_set_L: bytes = None) -> bytes:`

Calculate the aggregate public key from the participant keys.

##### `@classmethod pre_agg_key_transform(vkey: VerifyKey, key_set_L: bytes) -> bytes:`

Transform a participant VerifyKey prior to calculating the aggregate public key.
This is called by aggregate_public_keys on every participant VerifyKey.

##### `@classmethod encode_key_set(vkeys: list) -> bytes:`

Sort the participant keys into a deterministic order, then hash the list to
produce the keyset encoding (L).

### `Signature(AbstractSignature)`

A class that sums PartialSignatures into a full Signature.

#### Properties

- R: Aggregate nonce point.
- s: Aggregate signature made from summing partial signatures.
- M: Message to be signed.
- parts: Tuple of partial signatures summed together to create the signature.

#### Methods

##### `__init__(data: dict = None) -> None:`

Initialize an instance. Initialize with `{'parts': list_of_partial_sigs, 'M': bytes, 'R': bytes}`
to create a new signature from parts. Initialize with `{'s': bytes, 'R': bytes, 'M': bytes}`
to restore a signature.

##### `@classmethod from_bytes(data: bytes) -> Signature:`

Deserializes output from __bytes__.

##### `@classmethod create(R: bytes, M: bytes, parts: list[AbstractPartialSignature]) -> Signature:`

Create a new instance using the aggregate nonce point (R), the message (M), and
the list/tuple of partial signatures (scalars s_i).

### `ProtocolState(Enum)`

An enum containing all of the byte representations of possible protocol states
as encoded in ProtocolMessage or referenced in SigningSession.

### `ProtocolError(Exception)`

A custom error to be thrown if the SigningSession is configured to throw them.

#### Methods

##### `__init__(message: str, protocol_state: ProtocolState) -> None:`

##### `@classmethod from_bytes(bts: bytes) -> ProtocolError:`

Deserializes output from __bytes__.

##### `@classmethod from_str(s: str) -> ProtocolError:`

Deserializes output from __str__.

### `ProtocolMessage(AbstractProtocolMessage)`

A class that handles packing and unpacking messages for mediating the protocol.
This should be sufficient, but any other system can be used as long as the
SigningSession methods are called in the right manner and the right data is
communicated between parties in the right order. Multiple serialization options
are available for convenience.

#### Properties

- session_id: The UUID of the signing session for which this message was
constructed.
- state: The protocol state of the message.
- message: The message itself.
- message_parts: The things that serialize into and deserialize from
self.message.
- signature: The Signature result of add_signature.
- vkey: The VerifyKey used to verify the signature.

#### Methods

##### `__init__(data: dict = None) -> None:`

Initialize with json.loads output of json.dumps serialization to restore an
instance. Otherwise, it is better to use the create method.

##### `@classmethod from_bytes(data: bytes) -> ProtocolMessage:`

Deserialize from bytes using custom (but simple) serialization scheme.

##### `parse_message() -> None:`

Parses the message into parts based upon protocol state, e.g. lists of
participant keys, nonces, nonce commitments, etc, storing the result in
self.message_parts/self['message_parts'].

##### `add_signature(skey: SigningKey) -> ProtocolMessage:`

Add a signature to the message using the provided SigningKey. This signs the
protocol state + message, attaching the signature and the relevant VerifyKey to
the instance.

##### `check_signature() -> bool:`

Return true if and only if the instance contains a VerifyKey and a signature
valid for the protocol state + message, else return False.

##### `@classmethod create(id: UUID | None, state: ProtocolState, data: list) -> ProtocolMessage:`

Create a new instance with the given id, state, and data. If the state is EMPTY,
the id is ignored. If the state is SENDING_PARTICIPANT_KEY, ACK_PARTICIPANT_KEY,
REJECT_PARTICIPANT_KEY, AWAITING_COMMITMENT, AWAITING_NONCE, or
AWAITING_PARTIAL_SIGNATURE, the data must be a list of VerifyKey|bytes. If the
state is SENDING_COMMITMENT, ACK_COMMITMENT, or REJECT_COMMITMENT, the data must
be a list of NonceCommitment|bytes. If the state is SENDING_MESSAGE,
ACK_MESSAGE, or REJECT_MESSAGE, the data must be a list of str|bytes. If the
state is SENDING_NONCE, ACK_NONCE, or REJECT_NONCE, the data must be a list of
Nonce|bytes. If the state is SENDING_PARTIAL_SIGNATURE, ACK_PARTIAL_SIGNATURE,
or REJECT_PARTIAL_SIGNATURE, the data must be a list of PartialSignature|bytes.
If the state is COMPLETED, the data must be a Signature|bytes. If the state is
ABORTED, the data must be a ProtocolError|bytes.

### `SingleSigKey(AbstractSingleSigKey)`

A simple-to-use class that generates 1-of-1 MuSig signatures.

#### Properties

- skey: The SigningKey used for creating signatures.
- vkey: The aggregate public key for verifying signatures.
- vkey_base: The VerifyKey base used to calculate the aggregate public key.

#### Methods

##### `__init__(data: dict = None) -> None:`

Initialize using a nacl.signing.SigningKey or deserialize. Call with
`{'skey':SigningKey}` to create a new SingleSigKey. Call with a dict containing
json.loads output from a json.dumps serialization to restore an instance.

##### `@classmethod from_bytes(data: bytes) -> SingleSigKey:`

Deserializes output from __bytes__.

##### `sign_message(M: bytes) -> Signature:`

Sign a message (M) and return a Signature.

### `SigningSession(AbstractSigningSession)`

A class that handles multi-party signing sessions. This is designed to maintain
security with a 3-round protocol. Though the keys are reusable, each Session can
be used for only a single signature to avoid certain cryptographic attacks.
Nonce commitments (hash(R_i)) are pre-shared instead of public nonces (R_i) to
avoid vulnerability to the Wagner attack. Detailed documentation can be found in
the docs/musig.md file (eventually).

#### Properties

- id: The UUID of the session.
- number_of_participants: The number of participants expected to participate in
the protocol.
- protocol_state: The current state of the session.
- last_updated: A timestamp recording the last time the protocol state was
updated.
- skey: The SigningKey of the participant using this instance.
- vkeys: A tuple of participant VerifyKeys.
- nonce_commitments: A dict mapping participant VerifyKey to NonceCommitment.
- nonce_points: A dict mapping participant VerifyKey to Nonce. Note that the
Nonce for the participant using this instance will include the private scalar
value, but the Nonces of other participants will include only the public point
values.
- aggregate_nonce: The aggregate nonce point for the session.
- message: The message to be n-of-n signed.
- partial_signatures: A dict mapping participant VerifyKey to PartialSignature
(public values s_i only).
- public_key: The aggregate public key for the session.
- signature: The final n-of-n signature.

#### Methods

##### `__init__(data: dict = None) -> None:`

Init method. Initialize with None to create an EMPTY SigningSession. Initialize
with {'skey': SigningKey} to create an INITIALIZED SigningSession. Initialize
with a dict (output from json serialization/deserialization) to restore a
previously used or customly configured SigningSession.

##### `@classmethod from_bytes(data: bytes) -> SigningSession:`

Deserializes output from __bytes__.

##### `add_participant_keys(keys: VerifyKey | list[VerifyKey]) -> None:`

Add participant VerifyKey(s).

##### `add_nonce_commitment(commitment: NonceCommitment, vkey: VerifyKey) -> None:`

Add a NonceCommitment from a participant identified by the VerifyKey.

##### `add_nonce(nonce: Nonce, vkey: VerifyKey) -> None:`

Add a Nonce from a participant identified by the VerifyKey.

##### `make_partial_signature() -> PartialSignature:`

Create a partial signature to be broadcast to other participants.

##### `add_partial_signature(sig: PartialSignature, vkey: VerifyKey) -> None:`

Add a PartialSignature from a participant identified by the VerifyKey.

##### `update_protocol_state() -> None:`

Handle transitions between ProtocolStates as the SigningSession values are
updated. This is called automatically after any value is updated. The protocol
state will only update when the necessary conditions have been met.

## Functions

### `clamp_scalar(scalar: bytes | nacl.signing.SigningKey, from_private_key: bool = False) -> bytes:`

Make a clamped scalar.

### `aggregate_points(points: list) -> bytes:`

Aggregate points on the Ed25519 curve.

### `H_big(parts: bytes) -> bytes:`

The big, 64-byte hash function.

### `H_small(parts: bytes) -> bytes:`

The small, 32-byte hash function.

### `derive_key_from_seed(seed: bytes) -> bytes:`

Derive the scalar used for signing from a seed.

### `derive_challenge(L: bytes, X_i: bytes, X: bytes, R: bytes, M: bytes) -> bytes:`

Derive the challenge used for making a partial signature.

### `H_agg(L: bytes, X_i: bytes) -> bytes:`

The hash used for aggregating keys.

### `H_sig(R: bytes, X: bytes, M: bytes) -> bytes:`

The hash used to derive the challenge used in signing and verifying.

### `xor(b1: bytes, b2: bytes) -> bytes:`

XOR two equal-length byte strings together.

### `bytes_are_same(b1: bytes, b2: bytes) -> bool:`

Timing-attack safe bytes comparison.

### `version() -> str:`

Return the version of the package.

## Values

- `MAX_WAIT_TIME_FOR_COMMITMENTS`: int
- `MAX_WAIT_TIME_FOR_PUBLIC_NONCES`: int
- `MAX_WAIT_TIME_FOR_PARTIAL_SIGS`: int

