from .common import OQSSigner


ALGORITHM_ID = "FN-DSA-512"
IMPLEMENTATION = "Falcon-512"


class Signer(OQSSigner):
    """
    FN-DSA experimental signer.

    The available liboqs Falcon-512 implementation is used as the
    implementation corresponding to the FN-DSA lineage. Actual
    signature lengths are recorded by the experiment rather than
    assumed to be fixed.
    """

    def __init__(self, *, secret_key=None, public_key=None):
        super().__init__(
            IMPLEMENTATION, secret_key=secret_key, public_key=public_key
        )
