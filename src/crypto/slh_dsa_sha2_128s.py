from .common import OQSSigner


ALGORITHM_ID = "SLH-DSA-SHA2-128s"
IMPLEMENTATION = "SLH_DSA_PURE_SHA2_128S"


class Signer(OQSSigner):
    """SLH-DSA-SHA2-128s signer using liboqs."""

    def __init__(self):
        super().__init__(
            IMPLEMENTATION
        )