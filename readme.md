# MuSig

This is a simple-to-use implementation of the MuSig protocol, ported over from
the yet-unreleased [Pycelium-SDK](https://github.com/k98kurz/pycelium-sdk)
project (once the basics are finished, that project will be opened to the
public). This exists separately as a means to refactor the draft version of the
MuSig code and make it available to devs for experimentation earlier than the
rest of the SDK.

# Status

- [x] Migrate over all classes and functions.
- [x] Define abstract classes for type checking.
- [x] Refactor all classes to be maximally SOLID.
- [x] Standardize and clean up serialization/deserialization.
- [x] General code cleanup.
- [x] Add 1-of-1 and 2-of-2 examples.
- [x] MuSig documentation.
- [ ] Add adaptor signature system.
- [ ] Adaptor MuSig documentation.
- [ ] Publish as a package.
- [ ] Migrate final module back into Pycelium-SDK.

# Installation

Currently, this project is still in development, so the best way to install is
to clone the repo and then run the following from within the root directory
(assuming a Linix terminal):

```
python -m venv venv/
source venv/Scripts/activate
pip install -r requirements.txt
```

These instructions will change once development is complete and the module is
published as a package.

# Testing

Open a terminal in the root directory and run the following:

```
cd tests/
python -m unittest
```

# Usage

For details on the maths and safe use of the protocol, see docs/musig.md. The
below examples should be sufficient to get started using this module. There is
extensive type/value checking to enforce proper usage. If any bugs are encountered,
please submit the bug report by opening an issue in this repo.

## 1-of-1 MuSig

For 1-of-1 MuSig, use the SingleSigKey class as shown below.

```
from musig import SingleSigKey
from nacl.signing import SigningKey
from secrets import token_bytes

# do something to load a seed for private key creation, e.g.
seed = token_bytes()
skey = SigningKey(seed)
ssk = SingleSigKey({'skey': skey})

# sign a message and distribute along with public key for verification
message = b'hello world'
sig = ssk.sign_message(message)
pubkey = ssk.vkey

# to verify the signature, use the pubkey
assert pubkey.verify(sig)

# call str on any object to get the hex representation
# call repr on any object to get the jsonable dict representation
```

## n-of-n MuSig

For n-of-n MuSig, where n>1, use the SigningSession class as shown in the file
`example/2-of-2-musig.py`. In it, we are doing 2-of-2 MuSig for simplicity, but the process
works with any number of participants (though it has not been optimized for
absurdly large numbers of participants).

## Usage notes

The following classes have a `public` method that will return a copy with only
the values that are safe to share/distribute to others:
- `Nonce`
- `PartialSignature`
- `PublicKey`

It is important to call `public()` on these instances before sharing because the
objects will otherwise serialize with sensitive/private information.

Another thing to note is that all objects except ProtocolError (an exception)
and ProtocolState (which is an enum) can be serialized by passing it as an
argument for `str()`, `bytes()`, or `json.dumps()`, and those outputs can be
deserialized by calling `cls.from_str()`, `cls.from_bytes()`, and
`cls(json.loads())` respectively. ProtocolError can be serialized to and from
bytes and str, but it is not json compatible.

The final thing to note is that to make the objects serializable with the json
library, the classes inherit from the builtin dict class. To prevent misuse, the
`__setitem__` method has been rewritten to allow only those keys that map to a
defined property are allowed to be set with a value. For maximum json
compatibility, values are serialized to base64 where possible.

If you want to implement the abstract classes to build your own implementation
using the helper functions, or if you need some special functionality that the
included classes do not provide, it is notable that the `__init__` method must
be overwritten for json deserialization to function properly.
