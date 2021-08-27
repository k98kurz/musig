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
- [ ] General code cleanup.
- [ ] Full documentation.
- [ ] Migrate final module back into Pycelium-SDK.

# Installation

Installation instructions will be here once the package is published to pypi.

# Testing

Open a terminal in the root directory and run the following:

```
cd tests/
python -m unittest
```

# Usage

Usage instructions will be here once the refactoring is complete.
