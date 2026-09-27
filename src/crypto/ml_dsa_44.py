from .common import OQSSigner


ALGORITHM_ID = "ML-DSA-44"
IMPLEMENTATION = "ML-DSA-44"


class Signer(OQSSigner):
    """ML-DSA-44 signer using liboqs."""

    def __init__(self):
        super().__init__(
            IMPLEMENTATION
        )