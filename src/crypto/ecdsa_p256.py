from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


ALGORITHM_ID = "ECDSA-P256"
IMPLEMENTATION = "SECP256R1"


class Signer:
    """
    ECDSA P-256 signer.

    Signatures are represented as fixed-width r || s,
    with 32 bytes per component.
    """

    def __init__(self):
        self.private_key = ec.generate_private_key(
            ec.SECP256R1()
        )

        self.public_key = (
            self.private_key.public_key()
        )

    def public_key_bytes(self):
        """Serialize the public key as an uncompressed P-256 point."""
        numbers = (
            self.public_key.public_numbers()
        )

        x = numbers.x.to_bytes(
            32,
            byteorder="big"
        )

        y = numbers.y.to_bytes(
            32,
            byteorder="big"
        )

        return b"\x04" + x + y

    def export_secret_key(self):
        """Serialize only for a private local experiment checkpoint."""
        return self.private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @classmethod
    def from_secret_key(cls, secret_key, public_key):
        instance = cls.__new__(cls)
        instance.private_key = serialization.load_der_private_key(secret_key, password=None)
        if not isinstance(instance.private_key, ec.EllipticCurvePrivateKey) or not isinstance(instance.private_key.curve, ec.SECP256R1):
            raise ValueError("Checkpoint key must be ECDSA P-256.")
        instance.public_key = instance.private_key.public_key()
        if instance.public_key_bytes() != public_key:
            raise ValueError("Checkpoint public key does not match the private key.")
        return instance

    def sign(self, message):
        """Generate a fixed-width 64-byte ECDSA signature."""
        der_signature = self.private_key.sign(
            message,
            ec.ECDSA(
                hashes.SHA256()
            )
        )

        r, s = decode_dss_signature(
            der_signature
        )

        signature = (
            r.to_bytes(32, byteorder="big")
            + s.to_bytes(32, byteorder="big")
        )

        if len(signature) != 64:
            raise RuntimeError(
                "ECDSA P-256 signature is not 64 bytes."
            )

        return signature

    def verify(self, message, signature):
        """Verify a fixed-width r || s signature."""
        if len(signature) != 64:
            return False

        r = int.from_bytes(
            signature[:32],
            byteorder="big"
        )

        s = int.from_bytes(
            signature[32:],
            byteorder="big"
        )

        der_signature = encode_dss_signature(
            r,
            s
        )

        try:
            self.public_key.verify(
                der_signature,
                message,
                ec.ECDSA(
                    hashes.SHA256()
                )
            )

            return True

        except Exception:
            return False

    def metadata(self):
        """Return implementation metadata."""
        return {
            "backend": "cryptography",
            "implementation": IMPLEMENTATION,
            "public_key_bytes": len(
                self.public_key_bytes()
            ),
            "maximum_signature_bytes": 64,
            "signature_encoding": (
                "fixed-width r || s"
            ),
            "hash_function": "SHA-256",
        }

    def close(self):
        """No explicit resource release is required."""
        pass
