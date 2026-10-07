from .common import OQSSigner


ALGORITHM_ID = "ML-DSA-44"
IMPLEMENTATION = "ML-DSA-44"


class Signer(OQSSigner):
    """ML-DSA-44 signer using liboqs."""

    def __init__(self, *, secret_key=None, public_key=None):
        super().__init__(
            IMPLEMENTATION, secret_key=secret_key, public_key=public_key
        )
