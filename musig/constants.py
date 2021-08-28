"""Constants used for protecting against various types of Wagner/generalized
    birthday attacks. If a protocol step is not completed before the specified
    time has been passed, the protocol will abort and raise an error.
"""


MAX_WAIT_TIME_FOR_COMMITMENTS = 3600 # seconds; i.e. 1 hour
MAX_WAIT_TIME_FOR_PUBLIC_NONCES = 600 # seconds; i.e. 10 minutes
MAX_WAIT_TIME_FOR_PARTIAL_SIGS = 600 # seconds; i.e. 10 minutes