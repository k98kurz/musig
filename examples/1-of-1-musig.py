"""1-of-1 example"""


from musig import SingleSigKey
from nacl.signing import SigningKey, VerifyKey, SignedMessage
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

# alternatively use a VerifyKey
vkey = VerifyKey(bytes(pubkey.public()))
assert vkey.verify(SignedMessage(bytes(sig))) == message

# call str on any object to get the hex representation
# call repr on any object to get the jsonable dict representation
print(f'{str(sig)=}')
print(f'{repr(sig)=}\n')
print(f'{str(pubkey)=}')
print(f'{repr(pubkey)=}')
