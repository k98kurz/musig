# MuSig

This is a simple-to-use implementation of the MuSig protocol.

## Status

- [x] Migrate over all classes and functions.
- [x] Define abstract classes for type checking.
- [x] Refactor all classes to be maximally SOLID.
- [x] Standardize and clean up serialization/deserialization.
- [x] General code cleanup.
- [x] Add 1-of-1 and 2-of-2 examples.
- [x] MuSig documentation.
- [ ] Add adaptor signature system.
- [ ] Adaptor MuSig documentation.
- [ ] MuSig2 implementation.

## Installation

Currently, this project is still in development, so the best way to install is
to clone the repo and then run the following from within the root directory
(assuming a Linix terminal):

```
python -m venv venv/
source venv/bin/activate
pip install -r requirements.txt
```

On Windows, you may have to run `source venv/Scripts/activate`.

These instructions will change once development is complete and the module is
published as a package.

## Usage

For details on the maths and safe use of the protocol, see docs/musig.md. The
below examples should be sufficient to get started using this module. There is
extensive type/value checking to enforce proper usage. If any bugs are encountered,
please submit the bug report by opening an issue in this repo.

### 1-of-1 MuSig

For 1-of-1 MuSig, use the SingleSigKey class as shown in
`examples/1-of-1-musig.py`. This is unlikely to be useful in practice, but it is
hopefully helpful in making the process more understandable -- n-of-n MuSig
requires a minimum of 3 communication rounds, so the 1-of-1 SingleSigKey exists
to demonstrate the underlying maths in an uncomplicated way.

### n-of-n MuSig

For n-of-n MuSig, where n>1, use the SigningSession class as shown in the file
[examples/2-of-2-musig.py](https://github.com/k98kurz/musig/blob/master/examples/2-of-2-musig.py).
In it, we are doing 2-of-2 MuSig for simplicity, but the process works with any
number of participants (though it has not been optimized for absurdly large
numbers of participants).

### Usage notes

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
defined property to be set with a value. For maximum json compatibility, values
(and names of dict values) are serialized to base64 where possible/appropriate.

If you want to implement the abstract classes to build your own implementation
using the helper functions, or if you need some special functionality that the
included classes do not provide, it is notable that the `__init__` method must
be overwritten for json deserialization to function properly.

## Testing

Open a terminal in the root directory and run the following:

```
cd tests/
python -m unittest
```

## ISC License

Copyleft (c) 2021, Jonathan Voss (k98kurz)

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyleft notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
