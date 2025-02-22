"""2-of-2 example"""


from musig import (
    PublicKey,
    PartialSignature,
    SigningSession,
    ProtocolState,
    ProtocolMessage,
    ProtocolError,
    Nonce,
    NonceCommitment
)
from nacl.signing import SignedMessage, SigningKey, VerifyKey
from secrets import token_bytes


# simulate sending message
def send(pm: ProtocolMessage):
    print(f'message: {repr(pm)}')
    print(f'sending: {pm}\n')


# simulate receiving a message
def receive(pm: ProtocolMessage):
    print(f'received: {pm}')
    print(f'message: {repr(pm)}\n')
    return ProtocolMessage.from_bytes(bytes(pm))


def main():
    """Do something to load a seed for private key creation."""
    seed = token_bytes()
    skey = SigningKey(seed)

    """Initialize the session."""
    session = SigningSession({'skey': skey, 'number_of_participants': 2})

    """Create and add the values needed for this participant."""
    n = Nonce()
    nc = NonceCommitment.create(n)
    session.add_nonce_commitment(nc, skey.verify_key)
    session.add_nonce(n, skey.verify_key)

    """Simulate the other guy."""
    other_skey = SigningKey(token_bytes())
    pkey = PublicKey.create([skey.verify_key, other_skey.verify_key])
    other_n = Nonce()
    other_nc = NonceCommitment.create(other_n)
    agg_n = n + other_n
    other_ps = PartialSignature.create(other_skey, other_n.r, pkey.L, pkey.public(),
        agg_n.R, b'obviously a bitcoin transaction')

    """At this point, the state will be AWAITING_PARTICIPANT_KEYS.
        This can be communicated via use of the ProtocolMessage class, which will
        be demonstrated just for this step. Assume there are some methods, send
        and receive, that handle message exchange for us. I am excluding the
        receiving and parsing of ACK messages (and related resending of un-ACKed
        messages) for brevity.
    """
    pm = ProtocolMessage.create(session.id, session.protocol_state, [])
    pm = ProtocolMessage.create(session.id, ProtocolState.SENDING_PARTICIPANT_KEY, [other_skey.verify_key])
    pm = receive(pm.add_signature(other_skey))

    """Parse the message and add the key if possible."""
    try:
        if not pm.check_signature():
            raise Exception('broken signature')

        pm.parse_message()
        if pm.state is ProtocolState.SENDING_PARTICIPANT_KEY:
            vkey = pm.message_parts[0]
            session.add_participant_keys([vkey])
            """Acknowledge receipt of the key (optional)."""
            pm = ProtocolMessage.create(session.id, ProtocolState.ACK_PARTICIPANT_KEY, [vkey])
            send(pm.add_signature(session.skey))
    except ProtocolError as err:
        """Abort on a ProtocolError, communicating the error to peers first."""
        pm = ProtocolMessage.create(session.id, session.protocol_state, [err])
        send(pm.add_signature(session.skey))
        raise err
    except:
        """Retry or something here."""

    """State is now AWAITING_COMMITMENT, so send this participant's commitment."""
    pm = ProtocolMessage.create(session.id, ProtocolState.SENDING_COMMITMENT, [nc])
    send(pm.add_signature(session.skey))

    """Get the vkeys for missing nonce commitments and request those commitments."""
    vkeys = [vk for vk in session.vkeys if vk not in session.nonce_commitments.keys()]
    pm = ProtocolMessage.create(session.id, session.protocol_state, vkeys)
    send(pm.add_signature(session.skey))

    """Receive the commitment."""
    pm = receive(ProtocolMessage.create(
            session.id, ProtocolState.SENDING_COMMITMENT, [other_nc]
        ).add_signature(other_skey))
    try:
        pm.parse_message()
        if pm.state is ProtocolState.SENDING_COMMITMENT:
            nc = pm.message_parts[0]
            session.add_nonce_commitment(nc, pm.vkey)
            pm = ProtocolMessage.create(session.id, ProtocolState.ACK_COMMITMENT, [nc])
            send(pm.add_signature(session.skey))
    except ProtocolError as err:
        """Abort on a ProtocolError, communicating the error to peers first."""
        pm = ProtocolMessage.create(session.id, session.protocol_state, [err])
        send(pm.add_signature(session.skey))
        raise err
    except:
        """Retry or something here."""

    """At this point, I will exclude the message-passing simulation for brevity."""

    """State is now AWAITING_MESSAGE. Once the message is agreed upon, we advance."""
    session.message = b'obviously a bitcoin transaction'

    """State is now AWAITING_NONCE. Get the nonce point from the other participant.
        Once all nonce points are gathered, the aggregate nonce will be calculated.
    """
    try:
        session.add_nonce(other_n, other_skey.verify_key)
    except ProtocolError:
        """If the nonce does not match the commitment, if the vkey is not from a
            known participant, or if too much time has passed while waiting, an
            error will be raised, so deal with that here.
        """

    """State is now AWAITING_PARTIAL_SIGNATURE, so send ours and get theirs.
        Once all partial signatures are gathered, the aggregate signature will
        be calculated.
    """
    ps = session.make_partial_signature()
    session.add_partial_signature(ps, session.skey.verify_key)
    # send ps, receive received_ps and received_vkey
    try:
        session.add_partial_signature(other_ps, other_skey.verify_key)
    except ProtocolError as err:
        """If the received_vkey is not a known participant vkey, or if a
            conflicting partial signature is added when one already exists, an
            handle the error here.
        """

    """State should now be COMPLETE, so distribute the signature."""
    signature = session.signature
    assert session.public_key.verify(signature)
    print(f'{signature=}')
    print(f'{str(signature)=}')

    # compatible with ordinary Ed25519 signature verification
    sig = SignedMessage(bytes(signature))
    vkey = VerifyKey(bytes(session.public_key.public()))
    assert vkey.verify(sig) == session.message


if __name__ == '__main__':
    main()
