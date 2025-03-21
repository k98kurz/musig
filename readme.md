# MuSig

This is a simple-to-use implementation of the MuSig protocol.

## Status

Implementation of the original MuSig protocol is complete. Implementation of
MuSig2 is planned for a future release, as is an adaptor signature system.

Issues can be tracked [here](https://github.com/k98kurz/musig/issues).

## Installation

`pip install musig`

## Usage

For details on the maths and safe use of the protocol, see docs/musig.md. The
below examples should be sufficient to get started using this package. There is
extensive type/value checking to enforce proper usage. If any bugs are encountered,
please submit the bug report by opening an issue.

### 1-of-1 MuSig

For 1-of-1 MuSig, use the SingleSigKey class as shown in
[examples/1-of-1-musig.py](https://github.com/k98kurz/musig/blob/master/examples/1-of-1-musig.py).
This is unlikely to be useful in practice, but it is hopefully helpful in making
the process more understandable -- n-of-n MuSig requires a minimum of 3
communication rounds, so the 1-of-1 SingleSigKey exists to demonstrate the
underlying maths in an uncomplicated way.

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

```bash
python -m unittest discover -s tests
```

There are currently 128 unit tests and 3 e2e tests. The 1-of-1 and 2-of-2
examples were adapted as e2e tests, and a third e2e test demonstrates n-of-n
MuSig very concisely (omitting the message-passing simulation for brevity).

## More Resources

Documentation generated by [autodox](https://pypi.org/project/autodox) can be
found [here](https://github.com/k98kurz/musig/blob/master/dox.md), and old,
manually created documentation can be found
[here](https://github.com/k98kurz/musig/blob/master/docs/musig.md).

Check out the [Pycelium discord server](https://discord.gg/b2QFEJDX69). If you
experience a problem, please discuss it on the Discord server. All suggestions
for improvement are also welcome, and the best place for that is also Discord.
If you experience a bug and do not use Discord, open an issue on Github.

(NB: I wrote this library in 2021 and only just now got around to cleaning it up
enough to publish as a package. The code style and API are fairly idiosyncratic
and will likely be updated substantially in the future after getting feedback
and experience using it in practice.)

## ISC License

Copyleft (c) 2021-2025, Jonathan Voss (k98kurz)

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
