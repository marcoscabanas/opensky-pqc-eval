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

    def __init__(self, algorithm):
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

        self.signer = self.oqs.Signature(
            algorithm
        )

        self.public_key = (
            self.signer.generate_keypair()
        )

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