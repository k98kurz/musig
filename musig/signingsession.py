from __future__ import annotations
from base64 import b64decode
from json import dumps, loads
from musig.abstractclasses import AbstractSigningSession
from musig.constants import (
    MAX_WAIT_TIME_FOR_COMMITMENTS,
    MAX_WAIT_TIME_FOR_PARTIAL_SIGS,
    MAX_WAIT_TIME_FOR_PUBLIC_NONCES,
)
from musig.helpers import aggregate_points
from musig.nonce import Nonce
from musig.noncecommitment import NonceCommitment
from musig.partialsignature import PartialSignature
from musig.protocol import ProtocolState, ProtocolError
from musig.publickey import PublicKey
from musig.signature import Signature
from nacl.signing import SigningKey, VerifyKey
from time import time
from uuid import UUID, uuid4


class SigningSession(AbstractSigningSession):
    """A class that handles multi-party signing sessions.
        This is designed to maintain security with a 3-round protocol.
        Though the keys are reusable, each Session can be used for only a single
        signature to avoid certain cryptographic attacks. Nonce commitments
        (hash(R_i)) are pre-shared instead of public nonces (R_i) to avoid
        vulnerability to the Wagner attack. Detailed documentation can be found
        in the docs/musig.md file (eventually).
    """

    def __init__(self, data: dict = None) -> None:
        """Init method. Initialize with None to create an EMPTY SigningSession.
            Initialize with {'skey': SigningKey} to create an INITIALIZED SigningSession.
            Initialize with a dict (output from json serialization/deserialization)
            to restore a previously used or customly configured SigningSession.
        """
        self.last_updated = int(time() * 1000)

        if data is None:
            self.protocol_state = ProtocolState.EMPTY
            return

        if data is not None and type(data) is not dict:
            raise TypeError('data for initialization must be of type dict')

        if 'skey' in data:
            if type(data['skey']) is SigningKey:
                self.skey = data['skey']
            else:
                seed = data['skey'] if type(data['skey']) is bytes else b64decode(data['skey'])
                self.skey = SigningKey(seed)

            if 'id' not in data:
                # create an INITIALIZED session
                self.id = uuid4()
                self.vkeys = (self.skey.verify_key,)
                self.protocol_state = ProtocolState.INITIALIZED

        if 'id' in data:
            sid = data['id'] if type(data['id']) is bytes else b64decode(data['id'])
            self.id = UUID(bytes=sid)

        if 'protocol_state' in data:
            if type(data['protocol_state']) is ProtocolState:
                self.protocol_state = data['protocol_state']
            else:
                self.protocol_state = ProtocolState[data['protocol_state']]

        if 'number_of_participants' in data:
            self.number_of_participants = data['number_of_participants']

        if 'last_updated' in data:
            self.last_updated = data['last_updated']

        if 'vkeys' in data:
            vkeys = [vk if type(vk) in (bytes, VerifyKey) else b64decode(vk) for vk in data['vkeys']]
            self.vkeys = tuple([vk if type(vk) is VerifyKey else VerifyKey(vk) for vk in vkeys])

        if 'nonce_commitments' in data:
            commitments = {}
            for name in data['nonce_commitments']:
                n = VerifyKey(name if type(name) is bytes else b64decode(name))
                c = data['nonce_commitments'][name]
                c = c if type(c) is bytes else b64decode(c)
                commitments[n] = NonceCommitment.from_bytes(c)
            self.nonce_commitments = commitments

        if 'nonce_points' in data:
            nonce_points = {}
            for name in data['nonce_points']:
                n = VerifyKey(name if type(name) is bytes else b64decode(name))
                c = data['nonce_points'][name]
                c = c if type(c) is bytes else b64decode(c)
                nonce_points[n] = Nonce.from_bytes(c)
            self.nonce_points = nonce_points

        if 'aggregate_nonce' in data:
            n = data['aggregate_nonce']
            self.aggregate_nonce = Nonce.from_bytes(n if type(n) is bytes else b64decode(n))

        if 'message' in data:
            m = data['message']
            self.message = m if type(m) is bytes else b64decode(m)

        if 'partial_signatures' in data:
            parts = {}
            for name in data['partial_signatures']:
                n = VerifyKey(name if type(name) is bytes else b64decode(name))
                ps = data['partial_signatures'][name]
                parts[n] = PartialSignature.from_bytes(ps if type(ps) is bytes else b64decode(ps))
            self.partial_signatures = parts

        if 'public_key' in data:
            pk = data['public_key']
            self.public_key = PublicKey.from_bytes(pk if type(pk) is bytes else b64decode(pk))

        if 'signature' in data:
            s = data['signature']
            self.signature = Signature.from_bytes(s if type(s) is bytes else b64decode(s))

    def __setitem__(self, key, value) -> None:
        """Slightly modified __setitem__ for updating timestamps appropriately."""
        super().__setitem__(key, value)

        if key == 'protocol_state':
            self._protocol_state = value if type(value) is ProtocolState else ProtocolState[value]
            self.last_updated = int(time() * 1000)
        elif key == 'last_updated':
            ...
        else:
            self.update_protocol_state()

    def __bytes__(self) -> bytes:
        """Result of calling bytes() on instance; i.e. serialize to bytes."""
        return bytes(dumps(self), 'utf-8')

    @classmethod
    def from_bytes(cls, data: bytes) -> SigningSession:
        """Deserializes output from __bytes__."""
        if type(data) is not bytes:
            raise TypeError('data must be bytes')
        return SigningSession(loads(str(data, 'utf-8')))

    def add_participant_keys(self, keys: VerifyKey|list[VerifyKey]) -> None:
        """Add participant VerifyKey(s)."""
        if isinstance(keys, VerifyKey):
            keys = [keys]

        if type(keys) not in (list, tuple):
            raise TypeError('acceptable inputs are VerifyKey or list/tuple of the same')

        vkeys = list(self.vkeys)
        for k in keys:
            if not isinstance(k, VerifyKey):
                raise TypeError('acceptable inputs are VerifyKey or list/tuple of the same')
            if k not in self.vkeys:
                vkeys.append(k)

        self.vkeys = tuple(vkeys)

        if len(self.vkeys) == self.number_of_participants:
            # if all participant keys have been gathered, derive the aggregate public key
            self.public_key = PublicKey.create(list(self.vkeys))

    def add_nonce_commitment(self, commitment: NonceCommitment, vkey: VerifyKey) -> None:
        """Add a NonceCommitment from a participant identified by the VerifyKey."""
        if not isinstance(commitment, NonceCommitment):
            raise TypeError('commitment must be NonceCommitment')
        if not isinstance(vkey, VerifyKey):
            raise TypeError('vkey must be a VerifyKey')
        if vkey not in self.vkeys:
            raise ProtocolError('unrecognized vkey', ProtocolState.REJECT_COMMITMENT)
        if vkey in self.nonce_commitments.keys():
            self.protocol_state = ProtocolState.ABORTED
            raise ProtocolError('too many nonce commitments added for this vkey', ProtocolState.REJECT_COMMITMENT)

        # update in this round-about way to make use of setter and __setitem__ logic
        nonce_commitments = self.nonce_commitments
        nonce_commitments[vkey] = commitment

        self.nonce_commitments = nonce_commitments

    def add_nonce(self, nonce: Nonce, vkey: VerifyKey) -> None:
        """Add a Nonce from a participant identified by the VerifyKey."""
        if not isinstance(nonce, Nonce):
            raise TypeError('nonce must be Nonce')
        if not isinstance(vkey, VerifyKey):
            raise TypeError('vkey must be a VerifyKey')
        if vkey not in self.vkeys:
            raise ProtocolError('unrecognized vkey', ProtocolState.REJECT_NONCE)
        if vkey in self.nonce_points.keys():
            self.protocol_state = ProtocolState.ABORTED
            raise ProtocolError('too many nonces added for this vkey', ProtocolState.REJECT_NONCE)
        if vkey not in self.nonce_commitments.keys():
            raise ProtocolError('no NonceCommitment for this vkey', ProtocolState.REJECT_NONCE)

        nonce_points = self.nonce_points
        if not self.nonce_commitments[vkey].is_valid_for(nonce):
            # abort if the nonce does not validate for its commitment
            self.protocol_state = ProtocolState.ABORTED
            raise ProtocolError('Nonce invalid for NonceCommitment for this VerifyKey', ProtocolState.REJECT_NONCE)

        # update in this round-about way to make use of setter and __setitem__ logic
        nonce_points[vkey] = nonce
        self.nonce_points = nonce_points

    def make_partial_signature(self) -> PartialSignature:
        """Create a partial signature to be broadcast to other participants."""
        return PartialSignature.create(self.skey, self.nonce_points[self.skey.verify_key].r,
            self.public_key.L, self.public_key, self.aggregate_nonce.R, self.message)

    def add_partial_signature(self, sig: PartialSignature, vkey: VerifyKey) -> None:
        """Add a PartialSignature from a participant identified by the VerifyKey."""
        if not isinstance(sig, PartialSignature):
            raise TypeError('sig must be a PartialSignature')
        if not isinstance(vkey, VerifyKey):
            raise TypeError('vkey must be a VerifyKey')
        if vkey not in self.vkeys:
            raise ProtocolError('unrecognized vkey', ProtocolState.REJECT_PARTIAL_SIGNATURE)
        if vkey in self.partial_signatures.keys() and sig != self.partial_signatures[vkey]:
            self.protocol_state = ProtocolState.ABORTED
            raise ProtocolError('too many partial signatures added for this vkey', ProtocolState.REJECT_PARTIAL_SIGNATURE)

        # update in this round-about way to make use of setter and __setitem__ logic
        partial_signatures = self.partial_signatures
        partial_signatures[vkey] = sig
        self.partial_signatures = partial_signatures

    def update_protocol_state(self) -> None:
        """Handle transitions between ProtocolStates as the SigningSession values
            are updated. This is called automatically after any value is updated.
            The protocol state will only update when the necessary conditions
            have been met.
        """
        elapsed_time = int((time() * 1000 - self.last_updated)/1000)

        # abort conditions from misuse
        if self.number_of_participants is not None:
            if len(self.vkeys) > self.number_of_participants:
                self.protocol_state = ProtocolState.ABORTED
                raise ProtocolError('too many participant keys added', ProtocolState.REJECT_PARTICIPANT_KEY)
            if len(self.nonce_commitments.keys()) > self.number_of_participants:
                self.protocol_state = ProtocolState.ABORTED
                raise ProtocolError('too many nonce commitments added', ProtocolState.REJECT_COMMITMENT)

        if self.protocol_state is ProtocolState.EMPTY:
            if self.id is not None and self.skey is not None:
                self.protocol_state = ProtocolState.INITIALIZED

        if self.protocol_state is ProtocolState.INITIALIZED:
            if self.number_of_participants is not None and len(self.vkeys) < self.number_of_participants:
                self.protocol_state = ProtocolState.AWAITING_PARTICIPANT_KEY
            elif self.vkeys is not None and len(self.vkeys) == self.number_of_participants:
                self.protocol_state = ProtocolState.AWAITING_COMMITMENT

        if self.protocol_state is ProtocolState.AWAITING_PARTICIPANT_KEY:
            if self.vkeys is not None and len(self.vkeys) == self.number_of_participants:
                self.protocol_state = ProtocolState.AWAITING_COMMITMENT

        if self.protocol_state is ProtocolState.AWAITING_COMMITMENT:
            if elapsed_time > MAX_WAIT_TIME_FOR_COMMITMENTS:
                self.protocol_state = ProtocolState.ABORTED
                raise ProtocolError('maximum time elapsed awaiting nonce commitments', ProtocolState.TIME_EXCEEDED_AWAITING_COMMITMENT)
            if self.number_of_participants is not None:
                if len(self.nonce_commitments.keys()) == self.number_of_participants:
                    self.protocol_state = ProtocolState.AWAITING_MESSAGE

        if self.protocol_state is ProtocolState.AWAITING_MESSAGE:
            if self.message is not None:
                self.protocol_state = ProtocolState.AWAITING_NONCE

        if self.protocol_state is ProtocolState.AWAITING_NONCE:
            if elapsed_time > MAX_WAIT_TIME_FOR_PUBLIC_NONCES:
                self.protocol_state = ProtocolState.ABORTED
                raise ProtocolError('maximum time elapsed awaiting public nonces', ProtocolState.TIME_EXCEEDED_AWAITING_NONCE)
            if self.aggregate_nonce is not None:
                self.protocol_state = ProtocolState.AWAITING_PARTIAL_SIGNATURE
            elif self.number_of_participants is not None:
                if len(self.nonce_points.keys()) == self.number_of_participants:
                    points = [self.nonce_points[vk].R for vk in self.nonce_points]
                    self.aggregate_nonce = Nonce.from_bytes(aggregate_points(points))

        if self.protocol_state is ProtocolState.AWAITING_PARTIAL_SIGNATURE:
            if elapsed_time > MAX_WAIT_TIME_FOR_PARTIAL_SIGS:
                self.protocol_state = ProtocolState.ABORTED
                raise ProtocolError('maximum time elapsed awaiting partial signatures', ProtocolState.TIME_EXCEEDED_AWAITING_PARTIAL_SIGNATURE)
            if self.signature is not None:
                self.protocol_state = ProtocolState.COMPLETED
            elif self.number_of_participants is not None:
                if len(self.partial_signatures.keys()) == self.number_of_participants:
                    parts = [self.partial_signatures[vk] for vk in self.partial_signatures]
                    self.signature = Signature.create(self.aggregate_nonce.R, self.message, parts)

    @property
    def id(self) -> UUID|None:
        """The UUID of the session."""
        return self._id if hasattr(self, '_id') else None

    @id.setter
    def id(self, value: UUID):
        """The UUID of the session."""
        if not isinstance(value, UUID):
            raise TypeError('id must be a UUID')

        self['id'] = value.bytes
        self._id = value

    @property
    def number_of_participants(self) -> int|None:
        """The number of participants expected to participate in the protocol."""
        return self._number_of_participants if hasattr(self, '_number_of_participants') else None

    @number_of_participants.setter
    def number_of_participants(self, value: int):
        """The number of participants expected to participate in the protocol."""
        if not isinstance(value, int):
            raise TypeError('number_of_participants must be an int')

        self['number_of_participants'] = value

    @property
    def protocol_state(self) -> ProtocolState|None:
        """The current state of the session."""
        return self._protocol_state if hasattr(self, '_protocol_state') else None

    @protocol_state.setter
    def protocol_state(self, value: ProtocolState):
        """The current state of the session."""
        if not isinstance(value, ProtocolState):
            raise TypeError('protocol_state must be a ProtocolState')

        self['protocol_state'] = value.name

    @property
    def last_updated(self) -> int|None:
        """A timestamp recording the last time the protocol state was updated."""
        return self._last_updated if hasattr(self, '_last_updated') else None

    @last_updated.setter
    def last_updated(self, value: int):
        """A timestamp recording the last time the protocol state was updated."""
        if type(value) not in (float, int):
            raise TypeError('last_updated must be a timestamp')

        self['last_updated'] = int(value)

    @property
    def skey(self) -> SigningKey|None:
        """The SigningKey of the participant using this instance."""
        return self._skey if hasattr(self, '_skey') else None

    @skey.setter
    def skey(self, value: SigningKey):
        """The SigningKey of the participant using this instance."""
        if not isinstance(value, SigningKey):
            raise TypeError('skey must be a nacl.signing.SigningKey')

        self['skey'] = value

    @property
    def vkeys(self) -> tuple[VerifyKey, ...]:
        """A tuple of participant VerifyKeys."""
        return self._vkeys if hasattr(self, '_vkeys') else tuple()

    @vkeys.setter
    def vkeys(self, value: tuple[VerifyKey, ...]):
        """A tuple of participant VerifyKeys."""
        if type(value) not in (tuple, list):
            raise TypeError('vkeys must be a tuple or list of nacl.signing.VerifyKeys')

        for vk in value:
            if not isinstance(vk, VerifyKey):
                raise TypeError('vkeys must be a tuple or list of nacl.signing.VerifyKeys')

        self['vkeys'] = tuple(value)

    @property
    def nonce_commitments(self) -> dict[VerifyKey, NonceCommitment]:
        """A dict mapping participant VerifyKey to NonceCommitment."""
        return self._nonce_commitments if hasattr(self, '_nonce_commitments') else dict()

    @nonce_commitments.setter
    def nonce_commitments(self, value: dict[VerifyKey, NonceCommitment]):
        """A dict mapping participant VerifyKey to NonceCommitment."""
        if not isinstance(value, dict):
            raise TypeError('nonce_commitments must be a dict of form {VerifyKey:NonceCommitment}')

        for vk in value:
            nc = value[vk]
            if not isinstance(vk, VerifyKey):
                raise TypeError('nonce_commitments must be a dict of form {VerifyKey:NonceCommitment}')
            if not isinstance(nc, NonceCommitment):
                raise TypeError('nonce_commitments must be a dict of form {VerifyKey:NonceCommitment}')

        self['nonce_commitments'] = value

    @property
    def nonce_points(self) -> dict[VerifyKey, Nonce]:
        """A dict mapping participant VerifyKey to Nonce. Note that the Nonce
            for the participant using this instance will include the private
            scalar value, but the Nonces of other participants will include only
            the public point values.
        """
        return self._nonce_points if hasattr(self, '_nonce_points') else dict()

    @nonce_points.setter
    def nonce_points(self, value: dict[VerifyKey, Nonce]):
        """A dict mapping participant VerifyKey to Nonce. Note that the Nonce
            for the participant using this instance will include the private
            scalar value, but the Nonces of other participants will include only
            the public point values.
        """
        if not isinstance(value, dict):
            raise TypeError('nonce_points must be a dict of form {VerifyKey:Nonce}')

        for vk in value:
            n = value[vk]
            if not isinstance(vk, VerifyKey):
                raise TypeError('nonce_points must be a dict of form {VerifyKey:Nonce}')
            if not isinstance(n, Nonce):
                raise TypeError('nonce_points must be a dict of form {VerifyKey:Nonce}')

        self['nonce_points'] = value

    @property
    def aggregate_nonce(self) -> Nonce|None:
        """The aggregate nonce point for the session."""
        return self._aggregate_nonce if hasattr(self, '_aggregate_nonce') else None

    @aggregate_nonce.setter
    def aggregate_nonce(self, value: Nonce):
        """The aggregate nonce point for the session."""
        if not isinstance(value, Nonce):
            raise TypeError('aggregate_nonce must be a Nonce')

        self['aggregate_nonce'] = value

    @property
    def message(self) -> bytes|None:
        """The message to be n-of-n signed."""
        return self._message if hasattr(self, '_message') else None

    @message.setter
    def message(self, value: bytes|str):
        """The message to be n-of-n signed."""
        value = bytes(value, 'utf-8') if type(value) is str else value

        if type(value) is not bytes:
            raise TypeError('message must be bytes or str')

        self['message'] = value

    @property
    def partial_signatures(self) -> dict[VerifyKey, PartialSignature]:
        """A dict mapping participant VerifyKey to PartialSignature (public values s_i only)."""
        return self._partial_signatures if hasattr(self, '_partial_signatures') else dict()

    @partial_signatures.setter
    def partial_signatures(self, value: dict[VerifyKey, PartialSignature]):
        """A dict mapping participant VerifyKey to PartialSignature (public values s_i only)."""
        if not isinstance(value, dict):
            raise TypeError('partial_signatures must be a dict of form {VerifyKey:PartialSignature}')

        for vk in value:
            ps = value[vk]
            if not isinstance(vk, VerifyKey):
                raise TypeError('partial_signatures must be a dict of form {VerifyKey:PartialSignature}')
            if not isinstance(ps, PartialSignature):
                raise TypeError('partial_signatures must be a dict of form {VerifyKey:PartialSignature}')

        self['partial_signatures'] = value

    @property
    def public_key(self) -> PublicKey|None:
        """The aggregate public key for the session."""
        return self._public_key if hasattr(self, '_public_key') else None

    @public_key.setter
    def public_key(self, value: PublicKey):
        """The aggregate public key for the session."""
        if not isinstance(value, PublicKey):
            raise TypeError('public_key must be a PublicKey')

        self['public_key'] = value

    @property
    def signature(self) -> Signature|None:
        """The final n-of-n signature."""
        return self._signature if hasattr(self, '_signature') else None

    @signature.setter
    def signature(self, value: Signature):
        """The final n-of-n signature."""
        if not isinstance(value, Signature):
            raise TypeError('signature must be a Signature')

        self['signature'] = value
