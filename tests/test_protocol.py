from context import musig
from enum import Enum
from json import dumps, loads
from nacl.signing import SigningKey, VerifyKey, SignedMessage as NaclSignedMessage
from uuid import UUID, uuid4
import inspect
import musig
import unittest


class TestMuSigProtocol(unittest.TestCase):
    """Test suite for ProtocolState, ProtocolError, and ProtocolMessage."""
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

    # ProtocolState tests
    def test_ProtocolState_is_Enum(self):
        assert hasattr(musig, 'ProtocolState')
        assert inspect.isclass(musig.ProtocolState)
        assert issubclass(musig.ProtocolState, Enum)

    def test_ProtocolState_values_are_int(self):
        for attr in musig.ProtocolState:
            assert type(attr.value) is int

    # ProtocolError tests
    def test_ProtocolError_is_class_that_inherits_from_Exception(self):
        assert hasattr(musig, 'ProtocolError')
        assert inspect.isclass(musig.ProtocolError)
        assert issubclass(musig.ProtocolError, Exception)

    def test_ProtocolError_serializes_to_and_from_bytes_properly(self):
        for state in musig.ProtocolState:
            err0 = musig.ProtocolError('important information', state)
            err1 = musig.ProtocolError.from_bytes(bytes(err0))
            assert err0 == err1

    def test_ProtocolError_serializes_to_and_from_str_properly(self):
        for state in musig.ProtocolState:
            err0 = musig.ProtocolError('important information', state)
            err1 = musig.ProtocolError.from_str(str(err0))
            assert err0 == err1

    # ProtocolMessage tests
    def test_ProtocolMessage_is_a_class(self):
        assert hasattr(musig, 'ProtocolMessage')
        assert inspect.isclass(musig.ProtocolMessage)

    def test_ProtocolMessage_init_raises_ValueError_for_empty_or_incorrect_input(self):
        with self.assertRaises(ValueError):
            musig.ProtocolMessage()
        with self.assertRaises(ValueError):
            musig.ProtocolMessage({'state':'', 'not-message':''})
        with self.assertRaises(ValueError):
            musig.ProtocolMessage({'not-state':'', 'message':''})

    def test_ProtocolMessage_init_raises_TypeError_for_nondict_input(self):
        with self.assertRaises(TypeError):
            musig.ProtocolMessage('not a dict')
        with self.assertRaises(TypeError):
            musig.ProtocolMessage(b'not a dict')
        with self.assertRaises(TypeError):
            musig.ProtocolMessage(['not a dict'])

    def test_ProtocolMessage_create_raises_errors_for_improper_params(self):
        with self.assertRaises(TypeError):
            pm = musig.ProtocolMessage.create()
        with self.assertRaises(TypeError):
            pm = musig.ProtocolMessage.create('not a UUID', 'not a ProtocolState', 'not a list')
        with self.assertRaises(TypeError):
            pm = musig.ProtocolMessage.create('not a UUID', musig.ProtocolState.INITIALIZED, [])
        with self.assertRaises(TypeError):
            pm = musig.ProtocolMessage.create(self.uuid, 'not a ProtocolState', [])

    def test_ProtocolMessage_for_EMPTY(self):
        pm = musig.ProtocolMessage.create(None, musig.ProtocolState.EMPTY, [])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.EMPTY
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == b''
        assert hasattr(pm, 'session_id') and pm.session_id is None

        # add a signature
        pm.add_signature(self.signing_keys[0])
        assert hasattr(pm, 'signature') and type(pm.signature) is NaclSignedMessage
        assert hasattr(pm, 'vkey') and type(pm.vkey) is VerifyKey

        # test serialization and deserialization
        serialized = bytes(pm)
        assert type(serialized) is bytes
        assert len(serialized) > 0
        deserialized = musig.ProtocolMessage.from_bytes(serialized)
        assert isinstance(deserialized, musig.ProtocolMessage)
        assert deserialized == pm
        assert hasattr(deserialized, 'state') and deserialized.state is musig.ProtocolState.EMPTY
        assert hasattr(deserialized, 'message') and type(deserialized.message) is bytes
        assert deserialized.message == b''
        assert hasattr(deserialized, 'session_id') and deserialized.session_id is None

        # check deserialized message has valid signature
        assert deserialized.check_signature()

        # test json serialization and deserialization
        serialized = dumps(deserialized)
        deserialized = musig.ProtocolMessage(loads(serialized))
        assert deserialized.check_signature()
        assert bytes(deserialized) == bytes(pm)

    def test_ProtocolMessage_for_INITIALIZED(self):
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.INITIALIZED, [])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.INITIALIZED
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == b''
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # add a signature
        pm.add_signature(self.signing_keys[0])
        assert hasattr(pm, 'signature') and type(pm.signature) is NaclSignedMessage
        assert hasattr(pm, 'vkey') and type(pm.vkey) is VerifyKey

        # test serialization and deserialization
        serialized = bytes(pm)
        assert len(serialized) > 0
        deserialized = musig.ProtocolMessage.from_bytes(serialized)
        assert isinstance(deserialized, musig.ProtocolMessage)
        assert deserialized == pm

        # check deserialized message has valid signature
        assert deserialized.check_signature()

    def test_ProtocolMessage_for_AWAITING_PARTICIPANT_KEY(self):
        # scenario: self.signing_keys[0] is awaiting keys
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.AWAITING_PARTICIPANT_KEY, [])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.AWAITING_PARTICIPANT_KEY
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == b''
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # add a signature
        pm.add_signature(self.signing_keys[0])
        assert hasattr(pm, 'signature') and type(pm.signature) is NaclSignedMessage
        assert hasattr(pm, 'vkey') and type(pm.vkey) is VerifyKey

        # test serialization and deserialization
        serialized = bytes(pm)
        assert len(serialized) > 0
        deserialized = musig.ProtocolMessage.from_bytes(serialized)
        assert isinstance(deserialized, musig.ProtocolMessage)
        assert deserialized == pm

        # check deserialized message has valid signature
        assert deserialized.check_signature()

    def test_ProtocolMessage_for_SENDING_PARTICIPANT_KEY(self):
        # scenario: self.signing_keys[0] is sending its vkey
        vkey = self.signing_keys[0].verify_key
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.SENDING_PARTICIPANT_KEY, [vkey])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.SENDING_PARTICIPANT_KEY
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(vkey)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # add a signature
        pm.add_signature(self.signing_keys[0])
        assert hasattr(pm, 'signature') and type(pm.signature) is NaclSignedMessage
        assert hasattr(pm, 'vkey') and type(pm.vkey) is VerifyKey

        # test serialization and deserialization
        serialized = bytes(pm)
        assert len(serialized) > 0
        deserialized = musig.ProtocolMessage.from_bytes(serialized)
        assert isinstance(deserialized, musig.ProtocolMessage)
        assert deserialized == pm
        assert deserialized.message == bytes(vkey)

        # check deserialized message has valid signature
        assert deserialized.check_signature()

    def test_ProtocolMessage_for_ACK_PARTICIPANT_KEY(self):
        # scenario: self.signing_keys[0] is acknowledging receipt of a vkey
        vkey = self.signing_keys[1].verify_key
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.ACK_PARTICIPANT_KEY, [vkey])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.ACK_PARTICIPANT_KEY
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(vkey)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # scenario: self.signing_keys[0] is acknowledging receipt of 2 vkeys
        vkeys = self.verify_keys[1:]
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.ACK_PARTICIPANT_KEY, vkeys)
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.ACK_PARTICIPANT_KEY
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == b''.join([bytes(vk) for vk in vkeys])
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # add a signature
        pm.add_signature(self.signing_keys[0])
        assert hasattr(pm, 'signature') and type(pm.signature) is NaclSignedMessage
        assert hasattr(pm, 'vkey') and type(pm.vkey) is VerifyKey

        # test serialization and deserialization
        serialized = bytes(pm)
        assert len(serialized) > 0
        deserialized = musig.ProtocolMessage.from_bytes(serialized)
        assert isinstance(deserialized, musig.ProtocolMessage)
        assert deserialized == pm
        assert deserialized.message == b''.join([bytes(vk) for vk in vkeys])

        # check deserialized message has valid signature
        assert deserialized.check_signature()

    def test_ProtocolMessage_for_REJECT_PARTICIPANT_KEY(self):
        # scenario: self.signing_keys[0] is rejecting a vkey
        vkey = self.signing_keys[1].verify_key
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.REJECT_PARTICIPANT_KEY, [vkey])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.REJECT_PARTICIPANT_KEY
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(vkey)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # scenario: self.signing_keys[0] is rejecting 2 vkeys
        vkeys = self.verify_keys[1:]
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.REJECT_PARTICIPANT_KEY, vkeys)
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.REJECT_PARTICIPANT_KEY
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == b''.join([bytes(vk) for vk in vkeys])
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_AWAITING_COMMITMENT(self):
        # scenario: self.signing_keys[0] is awaiting nonce commitments from the other 2 participants
        vkeys = self.verify_keys[1:]
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.AWAITING_COMMITMENT, vkeys)
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.AWAITING_COMMITMENT
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == b''.join([bytes(vk) for vk in vkeys])
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_ACK_COMMITMENT(self):
        # scenario: self.signing_keys[0] is acknowledging receipt of a nonce commitment
        nc1 = musig.NonceCommitment.create(musig.Nonce())
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.ACK_COMMITMENT, [nc1])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.ACK_COMMITMENT
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(nc1)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # scenario: self.signing_keys[0] is acknowledging receipt of 2 nonce commitments
        nc2 = musig.NonceCommitment.create(musig.Nonce())
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.ACK_COMMITMENT, [nc1, nc2])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.ACK_COMMITMENT
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == b''.join([bytes(nc1), bytes(nc2)])
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # add a signature
        pm.add_signature(self.signing_keys[0])
        assert hasattr(pm, 'signature') and type(pm.signature) is NaclSignedMessage
        assert hasattr(pm, 'vkey') and type(pm.vkey) is VerifyKey

        # test serialization and deserialization
        serialized = bytes(pm)
        assert len(serialized) > 0
        deserialized = musig.ProtocolMessage.from_bytes(serialized)
        assert isinstance(deserialized, musig.ProtocolMessage)
        assert deserialized == pm
        assert hasattr(deserialized, 'state') and deserialized.state is musig.ProtocolState.ACK_COMMITMENT
        assert hasattr(deserialized, 'message') and type(deserialized.message) is bytes
        assert deserialized.message == b''.join([bytes(nc1), bytes(nc2)])
        assert hasattr(deserialized, 'session_id')
        assert isinstance(deserialized.session_id, UUID) and deserialized.session_id == self.uuid

        # check deserialized message has valid signature
        assert deserialized.check_signature()

    def test_ProtocolMessage_for_REJECT_COMMITMENT(self):
        # scenario: self.signing_keys[0] is rejecting a received nonce commitment
        nc1 = musig.NonceCommitment.create(musig.Nonce())
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.REJECT_COMMITMENT, [nc1])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.REJECT_COMMITMENT
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(nc1)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # scenario: self.signing_keys[0] is rejecting 2 received nonce commitments
        nc2 = musig.NonceCommitment.create(musig.Nonce())
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.REJECT_COMMITMENT, [nc1, nc2])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.REJECT_COMMITMENT
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == b''.join([bytes(nc1), bytes(nc2)])
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_SENDING_COMMITMENT(self):
        nc = musig.NonceCommitment.create(musig.Nonce())
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.SENDING_COMMITMENT, [nc])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.SENDING_COMMITMENT
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(nc)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_AWAITING_MESSAGE(self):
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.AWAITING_MESSAGE, [])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.AWAITING_MESSAGE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == b''
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_ACK_MESSAGE(self):
        msg = b'hello world'
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.ACK_MESSAGE, [msg])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.ACK_MESSAGE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == msg
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # test serialization and deserialization
        serialized = bytes(pm)
        assert len(serialized) > 0
        deserialized = musig.ProtocolMessage.from_bytes(serialized)
        assert isinstance(deserialized, musig.ProtocolMessage)
        assert deserialized == pm
        assert hasattr(deserialized, 'state') and deserialized.state is musig.ProtocolState.ACK_MESSAGE
        assert hasattr(deserialized, 'message') and type(deserialized.message) is bytes
        assert deserialized.message == msg
        assert hasattr(deserialized, 'session_id')
        assert isinstance(deserialized.session_id, UUID) and deserialized.session_id == self.uuid

    def test_ProtocolMessage_for_REJECT_MESSAGE(self):
        msg = b'hello world'
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.REJECT_MESSAGE, [msg])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.REJECT_MESSAGE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == msg
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_SENDING_MESSAGE(self):
        msg = b'hello world'
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.SENDING_MESSAGE, [msg])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.SENDING_MESSAGE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == msg
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_AWAITING_NONCE(self):
        # scenario: self.signing_keys[0] is awaiting nonces for other participants
        vkeys = self.verify_keys[1:]
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.AWAITING_NONCE, vkeys)
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.AWAITING_NONCE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == b''.join([bytes(vk) for vk in vkeys])
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # scenario: self.signing_keys[0] is awaiting nonces for self.signing_keys[1]
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.AWAITING_NONCE, [self.signing_keys[1].verify_key])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.AWAITING_NONCE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(self.signing_keys[1].verify_key)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_ACK_NONCE(self):
        # scenario: self.signing_keys[0] is acknowledging receipt of a nonce
        n1 = musig.Nonce().public()
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.ACK_NONCE, [n1])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.ACK_NONCE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(n1)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # scenario: self.signing_keys[0] is acknowledging receipt of nonces from others
        n2 = musig.Nonce().public()
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.ACK_NONCE, [n1, n2])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.ACK_NONCE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(n1) + bytes(n2)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # add a signature
        pm.add_signature(self.signing_keys[0])
        assert hasattr(pm, 'signature') and type(pm.signature) is NaclSignedMessage
        assert hasattr(pm, 'vkey') and type(pm.vkey) is VerifyKey

        # test bytes serialization and deserialization
        serialized = bytes(pm)
        assert len(serialized) > 0
        deserialized = musig.ProtocolMessage.from_bytes(serialized)
        assert isinstance(deserialized, musig.ProtocolMessage)
        assert deserialized == pm
        assert hasattr(deserialized, 'state') and deserialized.state is musig.ProtocolState.ACK_NONCE
        assert hasattr(deserialized, 'message') and type(deserialized.message) is bytes
        assert deserialized.message == bytes(n1) + bytes(n2)
        assert hasattr(deserialized, 'session_id')
        assert isinstance(deserialized.session_id, UUID) and deserialized.session_id == self.uuid

        # test str serialization and deserialization
        serialized = str(pm)
        deserialized = musig.ProtocolMessage.from_str(serialized)
        assert deserialized == pm

        # test json serialization and deserialization
        serialized = dumps(pm)
        deserialized = musig.ProtocolMessage(loads(serialized))
        assert deserialized == pm

        # check deserialized message has valid signature
        assert deserialized.check_signature()

    def test_ProtocolMessage_for_REJECT_NONCE(self):
        n = musig.Nonce().public()
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.REJECT_NONCE, [n])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.REJECT_NONCE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(n)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_SENDING_NONCE(self):
        n = musig.Nonce().public()
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.SENDING_NONCE, [n])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.SENDING_NONCE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(n)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_AWAITING_PARTIAL_SIGNATURE(self):
        # scenario: self.signing_key[0] is awaiting partial sigs from other participants
        vkeys = self.verify_keys[1:]
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.AWAITING_PARTIAL_SIGNATURE, vkeys)
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.AWAITING_PARTIAL_SIGNATURE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == b''.join([bytes(vk) for vk in vkeys])
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # scenario: self.signing_key[0] is awaiting partial sigs from self.signing_key[1]
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.AWAITING_PARTIAL_SIGNATURE, [self.signing_keys[1].verify_key])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.AWAITING_PARTIAL_SIGNATURE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(self.signing_keys[1].verify_key)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_ACK_PARTIAL_SIGNATURE(self):
        # scenario: self.signing_keys[0] is acknowledging receipt of a partial signature
        nonce = musig.Nonce()
        pkey = musig.PublicKey.create(self.verify_keys)
        skey = self.signing_keys[1]
        sig = musig.PartialSignature.create(skey, nonce.r, pkey.L, pkey, nonce.R, b'hello world')
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.ACK_PARTIAL_SIGNATURE, [sig])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.ACK_PARTIAL_SIGNATURE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(sig.public())
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_REJECT_PARTIAL_SIGNATURE(self):
        # scenario: self.signing_keys[0] is acknowledging receipt of a partial signature
        nonce = musig.Nonce()
        pkey = musig.PublicKey.create(self.verify_keys)
        skey = self.signing_keys[1]
        sig = musig.PartialSignature.create(skey, nonce.r, pkey.L, pkey, nonce.R, b'hello world')
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.REJECT_PARTIAL_SIGNATURE, [sig])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.REJECT_PARTIAL_SIGNATURE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(sig.public())
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # add a signature
        pm.add_signature(self.signing_keys[0])
        assert hasattr(pm, 'signature') and type(pm.signature) is NaclSignedMessage
        assert hasattr(pm, 'vkey') and type(pm.vkey) is VerifyKey

        # test serialization and deserialization
        serialized = bytes(pm)
        assert len(serialized) > 0
        deserialized = musig.ProtocolMessage.from_bytes(serialized)
        assert isinstance(deserialized, musig.ProtocolMessage)
        assert deserialized == pm
        assert hasattr(deserialized, 'state') and deserialized.state is musig.ProtocolState.REJECT_PARTIAL_SIGNATURE
        assert hasattr(deserialized, 'message') and type(deserialized.message) is bytes
        assert deserialized.message == bytes(sig.public())
        assert hasattr(deserialized, 'session_id')
        assert isinstance(deserialized.session_id, UUID) and deserialized.session_id == self.uuid

        # test str serialization and deserialization
        serialized = str(pm)
        deserialized = musig.ProtocolMessage.from_str(serialized)
        assert deserialized == pm

        # test json serialization and deserialization
        serialized = dumps(pm)
        deserialized = musig.ProtocolMessage(loads(serialized))
        assert deserialized == pm

        # check deserialized message has valid signature
        assert deserialized.check_signature()

    def test_ProtocolMessage_for_SENDING_PARTIAL_SIGNATURE(self):
        # scenario: self.signing_keys[0] is sending a partial sig
        nonce = musig.Nonce()
        pkey = musig.PublicKey.create(self.verify_keys)
        skey = self.signing_keys[0]
        sig = musig.PartialSignature.create(skey, nonce.r, pkey.L, pkey, nonce.R, b'hello world')
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.SENDING_PARTIAL_SIGNATURE, [sig])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.SENDING_PARTIAL_SIGNATURE
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(sig.public())
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

    def test_ProtocolMessage_for_COMPLETED(self):
        ssk = musig.SingleSigKey({'skey': self.signing_keys[0]})
        sig = ssk.sign_message(b'hello world')
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.COMPLETED, [sig])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.COMPLETED
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(sig)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # test serialization and deserialization
        serialized = bytes(pm)
        assert len(serialized) > 0
        deserialized = musig.ProtocolMessage.from_bytes(serialized)
        assert isinstance(deserialized, musig.ProtocolMessage)
        assert deserialized == pm
        assert hasattr(deserialized, 'state') and deserialized.state is musig.ProtocolState.COMPLETED
        assert hasattr(deserialized, 'message') and type(deserialized.message) is bytes
        assert pm.message == bytes(sig)
        assert hasattr(deserialized, 'session_id')
        assert isinstance(deserialized.session_id, UUID) and deserialized.session_id == self.uuid

    def test_ProtocolMessage_for_ABORTED(self):
        nc = musig.NonceCommitment.create(musig.Nonce().public())
        err = musig.ProtocolError(f'invalid nonce commitment: {nc}', musig.ProtocolState.REJECT_COMMITMENT)
        pm = musig.ProtocolMessage.create(self.uuid, musig.ProtocolState.ABORTED, [err])
        assert isinstance(pm, musig.ProtocolMessage)
        assert hasattr(pm, 'state') and pm.state is musig.ProtocolState.ABORTED
        assert hasattr(pm, 'message') and type(pm.message) is bytes
        assert pm.message == bytes(err)
        assert hasattr(pm, 'session_id')
        assert isinstance(pm.session_id, UUID) and pm.session_id == self.uuid

        # add a signature
        pm.add_signature(self.signing_keys[0])
        assert hasattr(pm, 'signature') and type(pm.signature) is NaclSignedMessage
        assert hasattr(pm, 'vkey') and type(pm.vkey) is VerifyKey

        # test serialization and deserialization
        serialized = bytes(pm)
        assert len(serialized) > 0
        deserialized = musig.ProtocolMessage.from_bytes(serialized)
        assert isinstance(deserialized, musig.ProtocolMessage)
        assert deserialized == pm
        assert hasattr(deserialized, 'state') and deserialized.state is musig.ProtocolState.ABORTED
        assert hasattr(deserialized, 'message') and type(deserialized.message) is bytes
        assert pm.message == bytes(err)
        assert hasattr(deserialized, 'session_id')
        assert isinstance(deserialized.session_id, UUID) and deserialized.session_id == self.uuid

        # check deserialized message has valid signature
        assert deserialized.check_signature()


if __name__ == '__main__':
    unittest.main()
