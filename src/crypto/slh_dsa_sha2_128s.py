from .common import OQSSigner


ALGORITHM_ID = "SLH-DSA-SHA2-128s"
IMPLEMENTATION = "SLH_DSA_PURE_SHA2_128S"


class Signer(OQSSigner):
    """SLH-DSA-SHA2-128s signer using liboqs."""

    def __init__(self, *, secret_key=None, public_key=None):
        super().__init__(
            IMPLEMENTATION, secret_key=secret_key, public_key=public_key
        )
