import importlib.metadata


def package_version(package_name):
    """Return the installed package version when available."""
    try:
        return importlib.metadata.version(
            package_name
        )
    except importlib.metadata.PackageNotFoundError:
        return None


def import_oqs():
    """Import liboqs-python and provide a clear error if unavailable."""
    try:
        import oqs
    except ImportError as exc:
        raise RuntimeError(
            "The Python package 'oqs' could not be imported. "
            "Install liboqs-python and ensure liboqs is available."
        ) from exc

    return oqs


class OQSSigner:
    """
    Common wrapper for liboqs signature implementations.
    """

    backend_name = "liboqs"

    def __init__(self, algorithm, *, secret_key=None, public_key=None):
        self.oqs = import_oqs()
        self.algorithm = algorithm

        enabled = set(
            self.oqs.get_enabled_sig_mechanisms()
        )

        if algorithm not in enabled:
            possible = sorted(
                name
                for name in enabled
                if (
                    algorithm.lower() in name.lower()
                    or name.lower() in algorithm.lower()
                )
            )

            message = (
                f"liboqs signature mechanism "
                f"'{algorithm}' is not enabled."
            )

            if possible:
                message += (
                    "\nPossible matching mechanisms:\n  "
                    + "\n  ".join(possible)
                )

            raise RuntimeError(message)

        if (secret_key is None) != (public_key is None):
            raise ValueError("Both secret and public keys are required for resume.")
        self.signer = self.oqs.Signature(algorithm)
        if secret_key is None:
            self.public_key = self.signer.generate_keypair()
        else:
            details = self.signer.details
            if (len(secret_key) != details["length_secret_key"]
                    or len(public_key) != details["length_public_key"]):
                self.signer.free()
                raise ValueError("Checkpoint key length does not match the algorithm.")
            self.signer.free()
            self.signer = self.oqs.Signature(algorithm, secret_key=secret_key)
            self.public_key = public_key

    def export_secret_key(self):
        """Serialize only for a private local experiment checkpoint."""
        return self.signer.export_secret_key()

    @classmethod
    def from_secret_key(cls, secret_key, public_key):
        return cls(secret_key=secret_key, public_key=public_key)

    def public_key_bytes(self):
        """Return the generated public key."""
        return self.public_key

    def sign(self, message):
        """Sign a byte string."""
        return self.signer.sign(
            message
        )

    def verify(self, message, signature):
        """Verify a signature against the generated public key."""
        return self.signer.verify(
            message,
            signature,
            self.public_key
        )

    def metadata(self):
        """Return implementation metadata reported by liboqs."""
        details = dict(
            self.signer.details
        )

        return {
            "backend": self.backend_name,
            "implementation": self.algorithm,
            "algorithm_version": details.get(
                "version"
            ),
            "claimed_nist_level": details.get(
                "claimed_nist_level"
            ),
            "public_key_bytes": details.get(
                "length_public_key"
            ),
            "secret_key_bytes": details.get(
                "length_secret_key"
            ),
            "maximum_signature_bytes": details.get(
                "length_signature"
            ),
        }

    def close(self):
        """Release liboqs resources."""
        self.signer.free()
