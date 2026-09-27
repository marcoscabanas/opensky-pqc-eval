#!/usr/bin/env python3

from src.crypto.ecdsa_p256 import Signer as ECDSASigner
from src.crypto.ml_dsa_44 import Signer as MLDSASigner
from src.crypto.fn_dsa_512 import Signer as FNDSASigner
from src.crypto.slh_dsa_sha2_128s import Signer as SLHDSASigner


TEST_MESSAGE = bytes.fromhex(
    "8D40621D58C382D690C8AC2863A7"
)


ALGORITHMS = {
    "ECDSA P-256": ECDSASigner,
    "ML-DSA-44": MLDSASigner,
    "FN-DSA-512": FNDSASigner,
    "SLH-DSA-SHA2-128s": SLHDSASigner,
}


def main():
    print("=== Cryptographic Smoke Test ===")
    print(f"Message: {TEST_MESSAGE.hex().upper()}")
    print(f"Message length: {len(TEST_MESSAGE)} bytes")

    for name, SignerClass in ALGORITHMS.items():
        print(f"\n--- {name} ---")

        signer = SignerClass()

        try:
            public_key = signer.public_key_bytes()

            signature = signer.sign(
                TEST_MESSAGE
            )

            valid = signer.verify(
                TEST_MESSAGE,
                signature
            )

            print(
                f"Public key: {len(public_key)} bytes"
            )
            print(
                f"Signature:  {len(signature)} bytes"
            )
            print(
                f"Verification: {valid}"
            )

            if not valid:
                raise RuntimeError(
                    f"{name} verification failed."
                )

            # Negative test:
            # Modify one bit of the original ADS-B message.
            tampered = bytearray(TEST_MESSAGE)
            tampered[0] ^= 0x01
            tampered = bytes(tampered)

            tampered_valid = signer.verify(
                tampered,
                signature
            )

            print(
                f"Tampered verification: "
                f"{tampered_valid}"
            )

            if tampered_valid:
                raise RuntimeError(
                    f"{name} accepted a modified message."
                )

            print("RESULT: PASS")

        finally:
            signer.close()

    print("\n=== ALL TESTS PASSED ===")


if __name__ == "__main__":
    main()