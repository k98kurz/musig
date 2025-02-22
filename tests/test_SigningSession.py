from context import musig
from json import dumps, loads
from nacl.signing import SigningKey
from time import time, sleep
from uuid import UUID, uuid4
import inspect
import musig
import unittest


class TestMuSigSigningSession(unittest.TestCase):
    """Test suite for SigningSession."""
    @classmethod
    def setUpClass(cls):
        cls.seeds = [
            'bc66e048abf92e97c35f00607a9260dd8299d91e698253c1090872d7d441df80',
            'a7a4b3a2afae8026fb6d523f06f67e5e69ca8e583881ca34574a8e6a9658eaec',
            'a5f496e55953105c5f80939f7a7794edcfd89997e801b6365effd35af1150b02'
        ]
        cls.seeds = [bytes.fromhex(seed) for seed in cls.seeds]
        cls.signing_keys = [SigningKey(seed) for seed in cls.seeds]
        cls.verify_keys = [sk.verify_key for sk in cls.signing_keys]
        cls.gvkey = 'eecb56e70d2405a849aa5e55b6e2f96aac2957dba72f8c289994c842e33ec477'
        cls.uuid = uuid4()

    def test_SigningSession_is_a_class(self):
        assert hasattr(musig, 'SigningSession')
        assert inspect.isclass(musig.SigningSession)

    def test_SigningSession__init__raises_TypeError_for_nondict_param(self):
        with self.assertRaises(TypeError) as err:
            musig.SigningSession('not a dict')
        assert str(err.exception) == 'data for initialization must be of type dict'

    def test_SigningSession__init__creates_EMPTY_instance_with_None_param(self):
        session = musig.SigningSession()
        assert isinstance(session, musig.SigningSession)
        assert hasattr(session, 'protocol_state')
        assert session.protocol_state is musig.ProtocolState.EMPTY
        assert session.id is None
        assert session.number_of_participants is None

    def test_SigningSession__init__creates_INITIALIZED_instance_with_only_skey_param(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        assert isinstance(session, musig.SigningSession)
        assert hasattr(session, 'protocol_state')
        assert session.protocol_state is musig.ProtocolState.INITIALIZED
        assert isinstance(session.id, UUID)
        assert len(session.vkeys) == 1

    def test_SigningSession__init__creates_AWAITING_PARTICIPANT_KEY_with_skey_and_number_of_participants(self):
        session = musig.SigningSession({'skey': self.signing_keys[0], 'number_of_participants': 2})
        assert isinstance(session, musig.SigningSession)
        assert hasattr(session, 'protocol_state')
        assert session.protocol_state is musig.ProtocolState.AWAITING_PARTICIPANT_KEY
        assert isinstance(session.id, UUID)
        assert len(session.vkeys) == 1

    def test_SigningSession_instances_enter_state_AWAITING_PARTICIPANT_KEY_after_setting_number_of_participants(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        assert session.protocol_state is musig.ProtocolState.INITIALIZED
        session.number_of_participants = 3
        assert session.protocol_state is musig.ProtocolState.AWAITING_PARTICIPANT_KEY

    def test_SigningSession_instance_has_add_participant_keys_method(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        assert hasattr(session, 'add_participant_keys')
        assert inspect.ismethod(session.add_participant_keys)

    def test_SigningSession_raises_ProtocolError_when_too_many_participant_keys_added(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = 2
        with self.assertRaises(musig.ProtocolError) as err:
            session.add_participant_keys(self.verify_keys)
        assert err.exception.message == 'too many participant keys added'
        assert err.exception.protocol_state == musig.ProtocolState.REJECT_PARTICIPANT_KEY
        assert session.protocol_state is musig.ProtocolState.ABORTED

    def test_SigningSession_add_participant_keys_raises_TypeError_on_invalid_param(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = 3
        with self.assertRaises(TypeError) as err:
            session.add_participant_keys(b'not a VerifyKey')
        assert str(err.exception) == 'acceptable inputs are VerifyKey or list/tuple of the same'
        with self.assertRaises(TypeError) as err:
            session.add_participant_keys(['still not a VerifyKey'])

    def test_SigningSession_last_updated_does_not_change_until_protocol_changes(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = 3
        assert len(session.vkeys) == 1
        assert session.public_key is None
        assert type(session.last_updated) is int
        start_time = session.last_updated
        assert session.last_updated == start_time
        assert session.protocol_state is musig.ProtocolState.AWAITING_PARTICIPANT_KEY
        session.add_participant_keys(self.verify_keys[:2])
        assert session.last_updated == start_time
        assert session.protocol_state is musig.ProtocolState.AWAITING_PARTICIPANT_KEY
        sleep(0.01)
        session.add_participant_keys(self.verify_keys[2])
        assert len(session.vkeys) == 3
        assert session.protocol_state is musig.ProtocolState.AWAITING_COMMITMENT
        assert session.last_updated != start_time

    def test_SigningSession_instances_at_state_AWAITING_COMMITMENT_have_public_key(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = len(self.signing_keys)
        assert len(session.vkeys) == 1
        assert session.public_key is None
        session.add_participant_keys(self.verify_keys)
        assert len(session.vkeys) == len(self.verify_keys)
        assert session.protocol_state is musig.ProtocolState.AWAITING_COMMITMENT
        assert hasattr(session, 'public_key')
        assert isinstance(session.public_key, musig.PublicKey)
        assert session.public_key.gvkey.hex() == self.gvkey

    def test_SigningSession_instance_has_add_nonce_commitment_method(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        assert hasattr(session, 'add_nonce_commitment')
        assert inspect.ismethod(session.add_nonce_commitment)

    def test_SigningSession_raises_PorotocolError_when_unrecognized_or_too_many_NonceCommitments_added(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = 2

        with self.assertRaises(musig.ProtocolError) as err:
            session.add_nonce_commitment(musig.NonceCommitment.create(musig.Nonce()), self.verify_keys[1])
        assert err.exception.protocol_state is musig.ProtocolState.REJECT_COMMITMENT
        assert err.exception.message == 'unrecognized vkey'
        assert session.protocol_state is musig.ProtocolState.AWAITING_PARTICIPANT_KEY

        session.add_participant_keys(self.verify_keys[:2])
        session.add_nonce_commitment(musig.NonceCommitment.create(musig.Nonce()), self.verify_keys[0])
        session.add_nonce_commitment(musig.NonceCommitment.create(musig.Nonce()), self.verify_keys[1])

        with self.assertRaises(musig.ProtocolError) as err:
            session.add_nonce_commitment(musig.NonceCommitment.create(musig.Nonce()), self.verify_keys[1])
        assert err.exception.protocol_state is musig.ProtocolState.REJECT_COMMITMENT
        assert err.exception.message == 'too many nonce commitments added for this vkey'
        assert session.protocol_state is musig.ProtocolState.ABORTED

        with self.assertRaises(musig.ProtocolError) as err:
            session.number_of_participants = 1

    def test_SigningSession_raises_PorotocolError_when_max_time_elapsed_before_collecting_all_NonceCommitments(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = 2
        session.add_participant_keys(self.verify_keys[:2])
        session.add_nonce_commitment(musig.NonceCommitment.create(musig.Nonce()), self.verify_keys[0])
        # simulate having arrived at protocol_state:AWAITING_COMMITMENT in the past
        assert session.protocol_state is musig.ProtocolState.AWAITING_COMMITMENT
        session.last_updated = (time() - musig.MAX_WAIT_TIME_FOR_COMMITMENTS - 100) * 1000
        with self.assertRaises(musig.ProtocolError) as err:
            session.add_nonce_commitment(musig.NonceCommitment.create(musig.Nonce()), self.verify_keys[1])
        assert err.exception.protocol_state is musig.ProtocolState.TIME_EXCEEDED_AWAITING_COMMITMENT
        assert err.exception.message == 'maximum time elapsed awaiting nonce commitments'
        assert session.protocol_state is musig.ProtocolState.ABORTED

    def test_SigningSession_enters_state_AWAITING_MESSAGE_after_receiving_all_NonceCommitments(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = len(self.verify_keys)
        session.add_participant_keys(self.verify_keys)
        for vk in self.verify_keys:
            session.add_nonce_commitment(musig.NonceCommitment.create(musig.Nonce()), vk)
        assert len(session.nonce_commitments) == session.number_of_participants
        assert session.protocol_state is musig.ProtocolState.AWAITING_MESSAGE

    def test_SigningSession_enters_state_AWAITING_NONCE_after_receiving_message(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = len(self.verify_keys)
        session.add_participant_keys(self.verify_keys)
        nonces = [musig.Nonce() for vk in self.verify_keys]
        nonces = zip(nonces, self.verify_keys)
        commitments = [musig.NonceCommitment.create(n[0]) for n in nonces]
        commitments = zip(commitments, self.verify_keys)
        for c in commitments:
            session.add_nonce_commitment(*c)
        assert session.protocol_state is musig.ProtocolState.AWAITING_MESSAGE
        session.message = 'hello world'
        assert session.protocol_state is musig.ProtocolState.AWAITING_NONCE

    def test_SigningSession_add_nonce_raises_TypeError_or_ProtocolError_if_params_invalid(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = len(self.verify_keys)
        session.add_participant_keys(self.verify_keys)
        nonces = [musig.Nonce() for vk in self.verify_keys]
        nonces = zip(nonces, self.verify_keys)
        commitments = [musig.NonceCommitment.create(n[0]) for n in nonces]
        commitments = zip(commitments, self.verify_keys)
        for c in commitments:
            session.add_nonce_commitment(c[0], c[1])
        session.message = 'hello world'

        assert session.protocol_state is musig.ProtocolState.AWAITING_NONCE
        with self.assertRaises(TypeError) as err:
            session.add_nonce('not a Nonce', self.verify_keys[0])
        with self.assertRaises(TypeError) as err:
            session.add_nonce(musig.Nonce(), 'not a VerifyKey')
        assert session.protocol_state is musig.ProtocolState.AWAITING_NONCE
        with self.assertRaises(musig.ProtocolError) as err:
            session.add_nonce(musig.Nonce(), self.verify_keys[0])
        assert err.exception.protocol_state is musig.ProtocolState.REJECT_NONCE
        assert err.exception.message == 'Nonce invalid for NonceCommitment for this VerifyKey'
        assert session.protocol_state == musig.ProtocolState.ABORTED

    def test_SigningSession_add_nonce_raises_ProtocolError_when_max_time_elapsed_before_collecting_all_Nonces(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = len(self.verify_keys)
        session.add_participant_keys(self.verify_keys)
        nonces = [musig.Nonce() for vk in self.verify_keys]
        nonces = list(zip(nonces, self.verify_keys))
        commitments = [musig.NonceCommitment.create(n[0]) for n in nonces]
        commitments = list(zip(commitments, self.verify_keys))
        for c in commitments:
            session.add_nonce_commitment(*c)
        session.message = 'hello world'
        # simulate having arrived at protocol_State:AWAITING_NONCE in the past
        assert session.protocol_state is musig.ProtocolState.AWAITING_NONCE
        session.last_updated = (time() - musig.MAX_WAIT_TIME_FOR_PUBLIC_NONCES - 100) * 1000
        with self.assertRaises(musig.ProtocolError) as err:
            session.add_nonce(*nonces[0])
        assert err.exception.protocol_state is musig.ProtocolState.TIME_EXCEEDED_AWAITING_NONCE
        assert err.exception.message == 'maximum time elapsed awaiting public nonces'
        assert session.protocol_state is musig.ProtocolState.ABORTED

    def test_SigningSession_enters_state_AWAITING_PARTIAL_SIGNATURE_after_all_Nonces_added(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = len(self.verify_keys)
        session.add_participant_keys(self.verify_keys)
        nonces = [musig.Nonce().public() for vk in self.verify_keys]
        nonces = list(zip(nonces, self.verify_keys))
        commitments = [musig.NonceCommitment.create(n[0]) for n in nonces]
        commitments = list(zip(commitments, self.verify_keys))
        for c in commitments:
            session.add_nonce_commitment(*c)
        session.message = 'hello world'
        assert session.protocol_state is musig.ProtocolState.AWAITING_NONCE
        for n in nonces:
            session.add_nonce(*n)
        assert len(session.nonce_points.keys()) == session.number_of_participants
        assert session.aggregate_nonce is not None
        assert session.protocol_state is musig.ProtocolState.AWAITING_PARTIAL_SIGNATURE

    def test_SigningSession_make_partial_signature_returns_PartialSignature(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = 2
        session.add_participant_keys(self.verify_keys[:2])
        nonces = [musig.Nonce() for vk in self.verify_keys[:2]]
        nonces = list(zip(nonces, self.verify_keys[:2]))
        commitments = [musig.NonceCommitment.create(n[0]) for n in nonces]
        commitments = list(zip(commitments, self.verify_keys[:2]))
        for c in commitments:
            session.add_nonce_commitment(*c)
        session.message = 'hello world'
        for n in nonces:
            session.add_nonce(*n)

        sig = session.make_partial_signature()
        assert isinstance(sig, musig.PartialSignature)

    def test_SigningSession_add_partial_signature_raises_TypeError_or_ProtocolError_if_params_invalid(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = 2
        session.add_participant_keys(self.verify_keys[:2])
        nonces = [musig.Nonce() for vk in self.verify_keys[:2]]
        nonces = list(zip(nonces, self.verify_keys[:2]))
        commitments = [musig.NonceCommitment.create(n[0]) for n in nonces]
        commitments = list(zip(commitments, self.verify_keys[:2]))
        for c in commitments:
            session.add_nonce_commitment(*c)
        session.message = 'hello world'
        for n in nonces:
            session.add_nonce(*n)
        assert session.protocol_state is musig.ProtocolState.AWAITING_PARTIAL_SIGNATURE

        sig = session.make_partial_signature()

        with self.assertRaises(TypeError):
            session.add_partial_signature('not a Partialsignature', self.verify_keys[0])
        with self.assertRaises(TypeError):
            session.add_partial_signature(sig, 'not a VerifyKey')
        with self.assertRaises(musig.ProtocolError) as err:
            session.add_partial_signature(sig, self.verify_keys[2])
        assert err.exception.protocol_state is musig.ProtocolState.REJECT_PARTIAL_SIGNATURE
        assert err.exception.message == 'unrecognized vkey'

        # set up a copy to get a different partial signature
        another_session = musig.SigningSession({**session})
        nonce_commitments = another_session.nonce_commitments
        nonce_points = another_session.nonce_points
        n = musig.Nonce()
        nc = musig.NonceCommitment.create(n)
        nonce_commitments[another_session.skey.verify_key] = nc
        another_session.nonce_commitments = nonce_commitments
        nonce_points[another_session.skey.verify_key] = n
        another_session.nonce_points = nonce_points
        another_sig = another_session.make_partial_signature()

        # we can add the same partial signature any number of times without problem
        session.add_partial_signature(sig, self.verify_keys[0])
        session.add_partial_signature(sig, self.verify_keys[0])
        session.add_partial_signature(sig, self.verify_keys[0])

        # but an error will be raised if a conflicting signature is added
        with self.assertRaises(musig.ProtocolError) as err:
            session.add_partial_signature(another_sig, self.verify_keys[0])
        assert err.exception.protocol_state is musig.ProtocolState.REJECT_PARTIAL_SIGNATURE
        assert err.exception.message == 'too many partial signatures added for this vkey'

    def test_SigningSession_add_partial_signatures_raises_ProtocolError_when_max_time_elapsed_before_collecting_all_PartialSignatures(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = 2
        session.add_participant_keys(self.verify_keys[:2])
        nonces = [musig.Nonce() for vk in self.verify_keys[:2]]
        nonces = list(zip(nonces, self.verify_keys[:2]))
        commitments = [musig.NonceCommitment.create(n[0]) for n in nonces]
        commitments = list(zip(commitments, self.verify_keys[:2]))
        for c in commitments:
            session.add_nonce_commitment(*c)
        session.message = 'hello world'
        for n in nonces:
            session.add_nonce(*n)
        # simulate having entered protocol_state:AWAITING_PARTIAL_SIGNATURE in the past
        session.last_updated = (time() - musig.MAX_WAIT_TIME_FOR_PARTIAL_SIGS - 100) * 1000
        assert session.protocol_state is musig.ProtocolState.AWAITING_PARTIAL_SIGNATURE

        sig = session.make_partial_signature()
        with self.assertRaises(musig.ProtocolError) as err:
            session.add_partial_signature(sig, self.verify_keys[0])
        assert err.exception.protocol_state is musig.ProtocolState.TIME_EXCEEDED_AWAITING_PARTIAL_SIGNATURE
        assert err.exception.message == 'maximum time elapsed awaiting partial signatures'
        assert session.protocol_state is musig.ProtocolState.ABORTED

    def test_SigningSession_enters_state_COMPLETE_after_all_PartialSignatures_added_and_signature_validates(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = len(self.verify_keys)
        session.add_participant_keys(self.verify_keys)
        nonces = [musig.Nonce() for vk in self.verify_keys]
        nonces = list(zip(nonces, self.verify_keys))
        commitments = [musig.NonceCommitment.create(n[0]) for n in nonces]
        commitments = list(zip(commitments, self.verify_keys))
        for c in commitments:
            session.add_nonce_commitment(*c)
        session.message = 'hello world'
        for n in nonces:
            session.add_nonce(*n)
        assert session.protocol_state is musig.ProtocolState.AWAITING_PARTIAL_SIGNATURE

        for i in range(len(self.signing_keys)):
            # NB: this works because the nonce_points are actually full nonces
            # In a realistic setting, only the nonce for the actual user will be
            # a full nonce, so hot-swapping SigningKeys won't work.
            session.skey = self.signing_keys[i]
            sig = session.make_partial_signature()
            session.add_partial_signature(sig, self.verify_keys[i])

        assert session.signature is not None
        assert session.protocol_state is musig.ProtocolState.COMPLETED

        assert session.public_key.verify(session.signature)

    def test_SigningSession_instances_serialize_and_deserialize_from_json(self):
        session = musig.SigningSession({'skey': self.signing_keys[0]})
        session.number_of_participants = len(self.verify_keys)
        session.add_participant_keys(self.verify_keys)

        serialized = dumps(session)
        deserialized = musig.SigningSession(loads(serialized))
        assert deserialized.id == session.id
        assert deserialized.protocol_state == session.protocol_state
        assert deserialized.number_of_participants == session.number_of_participants
        assert deserialized.last_updated == session.last_updated
        assert deserialized.skey == session.skey
        assert deserialized.vkeys == session.vkeys
        assert deserialized.nonce_commitments == session.nonce_commitments
        assert deserialized.nonce_points == session.nonce_points
        assert deserialized.aggregate_nonce == session.aggregate_nonce
        assert deserialized.message == session.message
        assert deserialized.partial_signatures == session.partial_signatures
        assert deserialized.public_key == session.public_key
        assert deserialized.signature == session.signature

        nonces = [musig.Nonce() for vk in self.verify_keys]
        nonces = list(zip(nonces, self.verify_keys))
        commitments = [musig.NonceCommitment.create(n[0]) for n in nonces]
        commitments = list(zip(commitments, self.verify_keys))
        for c in commitments:
            session.add_nonce_commitment(*c)

        serialized = dumps(session)
        deserialized = musig.SigningSession(loads(serialized))
        assert deserialized.id == session.id
        assert deserialized.protocol_state == session.protocol_state
        assert deserialized.number_of_participants == session.number_of_participants
        assert deserialized.last_updated == session.last_updated
        assert deserialized.skey == session.skey
        assert deserialized.vkeys == session.vkeys
        assert deserialized.nonce_commitments == session.nonce_commitments
        assert deserialized.nonce_points == session.nonce_points
        assert deserialized.aggregate_nonce == session.aggregate_nonce
        assert deserialized.message == session.message
        assert deserialized.partial_signatures == session.partial_signatures
        assert deserialized.public_key == session.public_key
        assert deserialized.signature == session.signature

        session.message = 'hello world'
        for n in nonces:
            session.add_nonce(*n)

        serialized = dumps(session)
        deserialized = musig.SigningSession(loads(serialized))
        assert deserialized.id == session.id
        assert deserialized.protocol_state == session.protocol_state
        assert deserialized.number_of_participants == session.number_of_participants
        assert deserialized.last_updated == session.last_updated
        assert deserialized.skey == session.skey
        assert deserialized.vkeys == session.vkeys
        assert deserialized.nonce_commitments == session.nonce_commitments
        assert deserialized.nonce_points == session.nonce_points
        assert deserialized.aggregate_nonce == session.aggregate_nonce
        assert deserialized.message == session.message
        assert deserialized.partial_signatures == session.partial_signatures
        assert deserialized.public_key == session.public_key
        assert deserialized.signature == session.signature

        for i in range(len(self.signing_keys)):
            session.skey = self.signing_keys[i]
            sig = session.make_partial_signature()
            session.add_partial_signature(sig, self.verify_keys[i])

        serialized = dumps(session)
        deserialized = musig.SigningSession(loads(serialized))
        assert deserialized.id == session.id
        assert deserialized.protocol_state == session.protocol_state
        assert deserialized.number_of_participants == session.number_of_participants
        assert deserialized.last_updated == session.last_updated
        assert deserialized.skey == session.skey
        assert deserialized.vkeys == session.vkeys
        assert deserialized.nonce_commitments == session.nonce_commitments
        assert deserialized.nonce_points == session.nonce_points
        assert deserialized.aggregate_nonce == session.aggregate_nonce
        assert deserialized.message == session.message
        assert deserialized.partial_signatures == session.partial_signatures
        assert deserialized.public_key == session.public_key
        assert deserialized.signature == session.signature


if __name__ == '__main__':
    unittest.main()
