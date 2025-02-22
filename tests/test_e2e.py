from context import musig
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from secrets import token_bytes
import unittest


class TestMuSigE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seeds = [token_bytes(32) for _ in range(3)]
        cls.signing_keys = [SigningKey(seed) for seed in cls.seeds]
        cls.verify_keys = [sk.verify_key for sk in cls.signing_keys]

    def test_1_of_1_musig(self):
        seed = token_bytes(32)
        skey = SigningKey(seed)
        ssk = musig.SingleSigKey({'skey': skey})
        message = b'hello world'
        sig = ssk.sign_message(message)
        pubkey = ssk.vkey
        assert pubkey.verify(sig)

        vkey = VerifyKey(bytes(pubkey.public()))
        assert vkey.verify(SignedMessage(bytes(sig))) == message

    def test_2_of_2_musig(self):
        # simulate sending a message
        def send(pm: musig.ProtocolMessage):
            ...
        # simulate receiving a message
        def receive(pm: musig.ProtocolMessage):
            return musig.ProtocolMessage.from_bytes(bytes(pm))

        # initialize the session
        session = musig.SigningSession({
            'skey': self.signing_keys[0],
            'number_of_participants': 2
        })

        # create and add the values needed for this participant
        n = musig.Nonce()
        nc = musig.NonceCommitment.create(n)
        session.add_nonce_commitment(nc, self.verify_keys[0])
        session.add_nonce(n, self.verify_keys[0])

        # simulate the other guy
        other_skey = self.signing_keys[1]
        pkey = musig.PublicKey.create([self.verify_keys[0], other_skey.verify_key])
        other_n = musig.Nonce()
        other_nc = musig.NonceCommitment.create(other_n)
        agg_n = n + other_n
        other_ps = musig.PartialSignature.create(other_skey, other_n.r, pkey.L, pkey.public(),
            agg_n.R, b'obviously a bitcoin transaction')

        # at this point, the state will be AWAITING_PARTICIPANT_KEYS
        # this can be communicated via use of the ProtocolMessage class, which will
        # be demonstrated just for this step. Assume there are some methods, send
        # and receive, that handle message exchange for us. I am excluding the
        # receiving and parsing of ACK messages (and related resending of un-ACKed
        # messages) for brevity.
        pm = musig.ProtocolMessage.create(session.id, session.protocol_state, [])
        pm = musig.ProtocolMessage.create(
            session.id, musig.ProtocolState.SENDING_PARTICIPANT_KEY, [other_skey.verify_key]
        )
        pm = receive(pm.add_signature(other_skey))

        # parse the message and add the key if possible
        try:
            if not pm.check_signature():
                raise Exception('broken signature')

            pm.parse_message()
            if pm.state is musig.ProtocolState.SENDING_PARTICIPANT_KEY:
                vkey = pm.message_parts[0]
                session.add_participant_keys([vkey])
                # Acknowledge receipt of the key (optional).
                pm = musig.ProtocolMessage.create(
                    session.id, musig.ProtocolState.ACK_PARTICIPANT_KEY, [vkey]
                )
                send(pm.add_signature(session.skey))
        except musig.ProtocolError as err:
            # Abort on a ProtocolError, communicating the error to peers first.
            pm = musig.ProtocolMessage.create(session.id, session.protocol_state, [err])
            send(pm.add_signature(session.skey))
            raise err
        except:
            # Retry or something here.
            pass

        # State is now AWAITING_COMMITMENT, so send this participant's commitment.
        pm = musig.ProtocolMessage.create(session.id, musig.ProtocolState.SENDING_COMMITMENT, [nc])
        send(pm.add_signature(session.skey))

        # Get the vkeys for missing nonce commitments and request those commitments.
        vkeys = [vk for vk in session.vkeys if vk not in session.nonce_commitments.keys()]
        pm = musig.ProtocolMessage.create(session.id, session.protocol_state, vkeys)
        send(pm.add_signature(session.skey))

        # Receive the commitment.
        pm = receive(musig.ProtocolMessage.create(
                session.id, musig.ProtocolState.SENDING_COMMITMENT, [other_nc]
            ).add_signature(other_skey))
        try:
            pm.parse_message()
            if pm.state is musig.ProtocolState.SENDING_COMMITMENT:
                nc = pm.message_parts[0]
                session.add_nonce_commitment(nc, pm.vkey)
                pm = musig.ProtocolMessage.create(session.id, musig.ProtocolState.ACK_COMMITMENT, [nc])
                send(pm.add_signature(session.skey))
        except musig.ProtocolError as err:
            # Abort on a ProtocolError, communicating the error to peers first.
            pm = musig.ProtocolMessage.create(session.id, session.protocol_state, [err])
            send(pm.add_signature(session.skey))
            raise err
        except:
            # Retry or something here.
            pass

        # At this point, I will exclude the message-passing simulation for brevity.

        # State is now AWAITING_MESSAGE. Once the message is agreed upon, we advance.
        session.message = b'obviously a bitcoin transaction'

        # State is now AWAITING_NONCE. Get the nonce point from the other participant.
        # Once all nonce points are gathered, the aggregate nonce will be calculated.
        try:
            session.add_nonce(other_n, other_skey.verify_key)
        except musig.ProtocolError:
            # If the nonce does not match the commitment, if the vkey is not from a
            # known participant, or if too much time has passed while waiting, an
            # error will be raised, so deal with that here.
            pass

        # State is now AWAITING_PARTIAL_SIGNATURE, so send ours and get theirs.
        # Once all partial signatures are gathered, the aggregate signature will
        # be calculated.
        ps = session.make_partial_signature()
        session.add_partial_signature(ps, session.skey.verify_key)
        # send ps, receive received_ps and received_vkey
        try:
            session.add_partial_signature(other_ps, other_skey.verify_key)
        except musig.ProtocolError as err:
            # If the received_vkey is not a known participant vkey, or if a
            # conflicting partial signature is added when one already exists, an
            # error will be raised, so handle the error here.
            pass

        # State should now be COMPLETE, so distribute the signature.
        signature = session.signature
        assert session.public_key.verify(signature)

        # compatible with ordinary Ed25519 signature verification
        sig = SignedMessage(bytes(signature))
        vkey = VerifyKey(bytes(session.public_key.public()))
        assert vkey.verify(sig) == session.message

    def test_3_of_3_musig(self):
        session = musig.SigningSession({
            'skey': self.signing_keys[0],
            'number_of_participants': 3
        })

        session.add_participant_keys(self.verify_keys)

        # create the aggregate public key
        pkey = musig.PublicKey.create(self.verify_keys)

        # simulate the other two participants
        nonces = [musig.Nonce() for _ in range(3)]
        nonce_commitments = [musig.NonceCommitment.create(n) for n in nonces]
        for i in range(3):
            session.add_nonce_commitment(nonce_commitments[i], self.verify_keys[i])
            session.add_nonce(nonces[i], self.verify_keys[i])

        # create partial signatures
        session.message = b'super important thing that must be authorized by a quorum'
        partial_signatures = [
            musig.PartialSignature.create(
                self.signing_keys[i],
                nonces[i].r,
                pkey.L,
                pkey.public(),
                session.aggregate_nonce.R,
                session.message
            )
            for i in range(3)
        ]
        for i in range(3):
            session.add_partial_signature(partial_signatures[i], self.verify_keys[i])

        # check the signature
        signature = session.signature
        assert session.public_key.verify(signature)


if __name__ == '__main__':
    unittest.main()
