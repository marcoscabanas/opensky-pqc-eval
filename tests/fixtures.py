"""Tiny synthetic records generated only inside automated tests."""

ALGORITHM = "ECDSA-P256"


def trace_fixture(count=3, spacing=0.2, aircraft=("ABCDEF", "123456"), offset=0.02):
    """Canonical 14-byte DF17 observations, with distinct payloads per aircraft."""
    return [
        {"trace_id": index * len(aircraft) + craft + 1, "icao": icao,
         "raw_msg": "8D" + icao + f"{index + 1:020X}",
         "relative_time_s": index * spacing + craft * offset}
        for index in range(count) for craft, icao in enumerate(aircraft)
    ]


def profile_fixture(sign_ms=0.1, verify_ms=0.1):
    return {
        "id": "test_constant_service",
        "algorithms": {ALGORITHM: {"operations": {
            operation: {"samples_ms": [duration], "sample_kind": "assumed_constant"}
            for operation, duration in (("sign", sign_ms), ("verify", verify_ms))
        }}},
    }
