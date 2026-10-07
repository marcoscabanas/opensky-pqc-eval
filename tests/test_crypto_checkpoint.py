import unittest

from src.crypto.ecdsa_p256 import Signer as ECDSA
from src.crypto.ml_dsa_44 import Signer as MLDSA
from src.crypto.fn_dsa_512 import Signer as FNDSA
from src.crypto.slh_dsa_sha2_128s import Signer as SLHDSA


class CryptoCheckpointTest(unittest.TestCase):
    def test_restored_aircraft_key_verifies_original_and_new_signatures(self):
        message = bytes.fromhex("8D40621D58C382D690C8AC2863A7")
        for factory in (ECDSA, MLDSA, FNDSA, SLHDSA):
            with self.subTest(algorithm=factory.__module__):
                original = factory()
                restored = None
                try:
                    signature = original.sign(message)
                    restored = factory.from_secret_key(
                        original.export_secret_key(), original.public_key_bytes(),
                    )
                    self.assertEqual(original.public_key_bytes(), restored.public_key_bytes())
                    self.assertTrue(restored.verify(message, signature))
                    self.assertTrue(original.verify(message, restored.sign(message)))
                    self.assertFalse(restored.verify(message + b"tampered", signature))
                    damaged = bytes([signature[0] ^ 1]) + signature[1:]
                    self.assertFalse(restored.verify(message, damaged))
                finally:
                    if restored is not None:
                        restored.close()
                    original.close()


if __name__ == "__main__":
    unittest.main()
