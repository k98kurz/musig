from base64 import b64encode, b64decode
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


class SigningSession(dict):
    """A class that handles multi-party signing sessions.
        This is designed to maintain security with a 3-round protocol.
        Though the keys are reusable, each Session can be used for only a single
        signature to avoid certain cryptographic attacks. Nonce commitments
        (hash(R_i)) are pre-shared instead of public nonces (R_i) to avoid
        vulnerability to the Wagner attack. Detailed documentation can be found
        in the musig.readme.md file (eventually).
    """

    def __init__(self, data=None) -> None:
        """Init method. Initialize with None to create an EMPTY SigningSession.
            Initialize with a SigningKey to create an INITIALIZED SigningSession.
        """
        self.last_updated = time() * 1000

        if data is None:
            self._protocol_state = ProtocolState.EMPTY

        if isinstance(data, SigningKey):
            self.skey = data
            self.id = uuid4()
            self.vkeys = (data.verify_key,)
            self.protocol_state = ProtocolState.INITIALIZED

        if isinstance(data, dict):
            super().__init__(data)
            self.deserialize()

    def __setitem__(self, key, value) -> None:
        if hasattr(self, key):
            setattr(self, f'_{key}', value)
            if type(value) in (int, str):
                super().__setitem__(key, value)
            elif type(value) is bytes:
                super().__setitem__(key, b64encode(value).decode())
            elif type(value) in (tuple, list):
                super().__setitem__(key, tuple([b64encode(bytes(k)).decode() for k in value]))
            elif type(value) is dict:
                nv = {}
                for name in value:
                    val = value[name]
                    name = name if type(name) is str else bytes(name)
                    val = val if type(val) is str else bytes(val)
                    nv[b64encode(name).decode()] = b64encode(val).decode()
                super().__setitem__(key, nv)
            else:
                super().__setitem__(key, b64encode(bytes(value)).decode())

        if key == 'id':
            self._id = UUID(bytes=value) if type(value) is bytes else value

        if key == 'protocol_state':
            self._protocol_state = value if type(value) is ProtocolState else ProtocolState[value]
            self.last_updated = time() * 1000
        elif key == 'last_updated':
            self._last_updated = value
        else:
            self.update_protocol_state()

    def add_participant_keys(self, keys) -> None:
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
            self.public_key = PublicKey(list(self.vkeys))

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

        nonce_commitments = self.nonce_commitments
        nonce_commitments[vkey] = commitment

        self.nonce_commitments = nonce_commitments

    def add_nonce(self, nonce: Nonce, vkey: VerifyKey) -> None:
        """Add a NonceCommitment from a participant identified by the VerifyKey."""
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
            self.protocol_state = ProtocolState.ABORTED
            raise ProtocolError('Nonce invalid for NonceCommitment for this VerifyKey', ProtocolState.REJECT_NONCE)

        nonce_points[vkey] = nonce
        self.nonce_points = nonce_points

    def make_partial_signature(self) -> PartialSignature:
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
        if vkey in self.partial_signatures.keys():
            self.protocol_state = ProtocolState.ABORTED
            raise ProtocolError('too many partial signatures added for this vkey', ProtocolState.REJECT_PARTIAL_SIGNATURE)

        partial_signatures = self.partial_signatures
        partial_signatures[vkey] = sig
        self.partial_signatures = partial_signatures

    def update_protocol_state(self) -> None:
        """Handle transitions between ProtocolStates as the SigningSession values
            are updated.
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
                    self.aggregate_nonce = Nonce(aggregate_points(points))

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

    def deserialize(self) -> None:
        """Called when the results of a json.loads call are passed to __init__."""
        if 'id' in self:
            self._id = UUID(bytes=b64decode(self['id']))
        if 'protocol_state' in self:
            self._protocol_state = ProtocolState[self['protocol_state']]
        if 'number_of_participants' in self:
            self._number_of_participants = self['number_of_participants']
        if 'last_updated' in self:
            self._last_updated = self['last_updated']
        if 'skey' in self:
            self._skey = SigningKey(b64decode(self['skey']))
        if 'vkeys' in self:
            self._vkeys = tuple([VerifyKey(b64decode(vk)) for vk in self['vkeys']])
        if 'nonce_commitments' in self:
            commitments = {}
            for name in self['nonce_commitments']:
                n = VerifyKey(b64decode(name))
                commitments[n] = NonceCommitment(b64decode(self['nonce_commitments'][name]))
            self._nonce_commitments = commitments
        if 'nonce_points' in self:
            nonce_points = {}
            for name in self['nonce_points']:
                n = VerifyKey(b64decode(name))
                nonce_points[n] = Nonce(b64decode(self['nonce_points'][name]))
            self._nonce_points = nonce_points
        if 'aggregate_nonce' in self:
            self._aggregate_nonce = Nonce(b64decode(self['aggregate_nonce']))
        if 'message' in self:
            self._message = b64decode(self['message'])
        if 'partial_signatures' in self:
            parts = {}
            for name in self['partial_signatures']:
                n = VerifyKey(b64decode(name))
                parts[n] = PartialSignature(b64decode(self['partial_signatures'][name]))
            self._partial_signatures = parts
        if 'public_key' in self:
            self._public_key = PublicKey(b64decode(self['public_key']))
        if 'signature' in self:
            self._signature = Signature(b64decode(self['signature']))

    @property
    def id(self):
        return self._id if hasattr(self, '_id') else None

    @id.setter
    def id(self, value):
        if not isinstance(value, UUID):
            raise TypeError('id must be a UUID')
        self['id'] = value.bytes

    @property
    def number_of_participants(self):
        return self._number_of_participants if hasattr(self, '_number_of_participants') else None

    @number_of_participants.setter
    def number_of_participants(self, value):
        if not isinstance(value, int):
            raise TypeError('number_of_participants must be an int')
        self['number_of_participants'] = value

    @property
    def protocol_state(self):
        return self._protocol_state if hasattr(self, '_protocol_state') else None

    @protocol_state.setter
    def protocol_state(self, value):
        if not isinstance(value, ProtocolState):
            raise TypeError('protocol_state must be a ProtocolState')
        self['protocol_state'] = value.name

    @property
    def last_updated(self):
        return self._last_updated if hasattr(self, '_last_updated') else None

    @last_updated.setter
    def last_updated(self, value):
        if type(value) not in (float, int):
            raise TypeError('last_updated must be a timestamp')
        self['last_updated'] = int(value)

    @property
    def skey(self):
        return self._skey if hasattr(self, '_skey') else None

    @skey.setter
    def skey(self, value):
        if not isinstance(value, SigningKey):
            raise TypeError('skey must be a nacl.signing.SigningKey')
        self['skey'] = value

    @property
    def vkeys(self):
        return self._vkeys if hasattr(self, '_vkeys') else tuple()

    @vkeys.setter
    def vkeys(self, value):
        value = tuple(value) if type(value) is list else value

        if type(value) is not tuple:
            raise TypeError('vkeys must be a tuple or list of nacl.signing.VerifyKeys')

        for vk in value:
            if not isinstance(vk, VerifyKey):
                raise TypeError('vkeys must be a tuple or list of nacl.signing.VerifyKeys')

        self['vkeys'] = value

    @property
    def nonce_commitments(self):
        return self._nonce_commitments if hasattr(self, '_nonce_commitments') else dict()

    @nonce_commitments.setter
    def nonce_commitments(self, value):
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
    def nonce_points(self):
        return self._nonce_points if hasattr(self, '_nonce_points') else dict()

    @nonce_points.setter
    def nonce_points(self, value):
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
    def aggregate_nonce(self):
        return self._aggregate_nonce if hasattr(self, '_aggregate_nonce') else None

    @aggregate_nonce.setter
    def aggregate_nonce(self, value):
        if not isinstance(value, Nonce):
            raise TypeError('aggregate_nonce must be a Nonce')

        self['aggregate_nonce'] = value

    @property
    def message(self):
        return self._message if hasattr(self, '_message') else None

    @message.setter
    def message(self, value):
        value = bytes(value, 'utf-8') if type(value) is str else value

        if type(value) is not bytes:
            raise TypeError('message must be bytes or str')

        self['message'] = value

    @property
    def partial_signatures(self):
        return self._partial_signatures if hasattr(self, '_partial_signatures') else dict()

    @partial_signatures.setter
    def partial_signatures(self, value):
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
    def public_key(self):
        return self._public_key if hasattr(self, '_public_key') else None

    @public_key.setter
    def public_key(self, value):
        if not isinstance(value, PublicKey):
            raise TypeError('public_key must be a PublicKey')

        self['public_key'] = value

    @property
    def signature(self):
        return self._signature if hasattr(self, '_signature') else None

    @signature.setter
    def signature(self, value):
        if not isinstance(value, Signature):
            raise TypeError('signature must be a Signature')

        self['signature'] = value
