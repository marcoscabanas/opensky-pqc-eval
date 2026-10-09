"""Read-only numerical and metadata comparison against the Zenodo reference.

This standard-library command complements the experiment's --validate-only
checks. It does not verify signatures, validate scientific assumptions, or
certify the source code that produced a local table.
"""

import argparse
import csv
from dataclasses import dataclass, field
from decimal import Decimal
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[2]
KEY_FIELDS = ("algorithm", "interval_k", "scenario", "seed")
RELATIVE_TOLERANCE = Decimal("1e-9")
ABSOLUTE_TOLERANCE = Decimal("1e-9")
MAX_DISPLAYED_DIFFERENCES = 20
NUMBER = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?\Z")


def _digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reject_constant(value):
    raise ValueError(f"Nonfinite numeric value is not allowed: {value}")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _json(value, *, decimals=False):
    return json.loads(value, object_pairs_hook=_unique_object,
                      parse_float=Decimal if decimals else float,
                      parse_constant=_reject_constant)


def _cell(value):
    """Keep integer counts exact, including integers inside nested JSON."""
    if value == "":
        return None
    stripped = value.strip()
    if stripped in ("True", "true"):
        return True
    if stripped in ("False", "false"):
        return False
    if stripped == "null":
        return None
    if stripped.lower() in ("nan", "inf", "infinity", "+inf", "-inf",
                            "+infinity", "-infinity", "+nan", "-nan"):
        raise ValueError(f"Nonfinite numeric value is not allowed: {value}")
    if NUMBER.fullmatch(stripped):
        return Decimal(stripped) if any(c in stripped for c in ".eE") else int(stripped)
    # The table also contains the literal interval notation "[start,end)".
    # Only bracket pairs denoting JSON arrays should be decoded as arrays.
    if stripped.startswith("{") or (stripped.startswith("[") and stripped.endswith("]")):
        return _json(stripped, decimals=True)
    return value


def read_table(contents, label):
    """Parse a nonempty table; fail on missing columns, rows, or case identity."""
    csv.field_size_limit(max(csv.field_size_limit(), len(contents)))
    reader = csv.DictReader(io.StringIO(contents.decode("utf-8-sig"), newline=""))
    columns = reader.fieldnames
    if not columns or len(set(columns)) != len(columns) or any(not c for c in columns):
        raise ValueError(f"{label}: missing or duplicate CSV column names")
    if not set(KEY_FIELDS).issubset(columns):
        raise ValueError(f"{label}: required case columns are {', '.join(KEY_FIELDS)}")
    rows = {}
    for line, raw in enumerate(reader, start=2):
        if None in raw or any(value is None for value in raw.values()):
            raise ValueError(f"{label}: malformed CSV row {line}")
        try:
            row = {column: _cell(value) for column, value in raw.items()}
        except ValueError as error:
            raise ValueError(f"{label}: row {line}: {error}") from error
        for column in ("algorithm", "scenario"):
            if not isinstance(row[column], str) or not row[column].strip():
                raise ValueError(f"{label}: row {line}: invalid {column}")
        for column, minimum in (("interval_k", 1), ("seed", 0)):
            value = row[column]
            if type(value) not in (int, Decimal) or value != int(value) or value < minimum:
                raise ValueError(f"{label}: row {line}: invalid {column}")
            row[column] = int(value)
        key = tuple(row[column] for column in KEY_FIELDS)
        if key in rows:
            raise ValueError(f"{label}: duplicate case {key}")
        rows[key] = row
    if not rows:
        raise ValueError(f"{label}: no replay cases")
    return frozenset(columns), rows


def _check_record(record, contents, label):
    if type(record.get("bytes")) is not int or record["bytes"] < 0:
        raise ValueError(f"{label}: invalid declared byte count")
    if len(contents) != record["bytes"] or hashlib.sha256(contents).hexdigest() != record.get("sha256"):
        raise ValueError(f"{label}: checksum or byte-count mismatch")


def reference_tables(artifacts_dir, windows):
    """Verify the downloaded archive and requested reference members in memory."""
    manifest = _json((artifacts_dir / "artifact_manifest.json").read_text(encoding="utf-8"))
    if (not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list)
            or any(not isinstance(entry, dict) for entry in manifest["files"])):
        raise ValueError("Artifact manifest must be an object containing a list of file records")
    entries = [entry for entry in manifest["files"]
               if entry.get("filename") == "metadata-and-results.zip"]
    if len(entries) != 1:
        raise ValueError("Manifest must contain exactly one metadata-and-results.zip")
    record = entries[0]
    archive = artifacts_dir / "metadata-and-results.zip"
    if (type(record.get("bytes")) is not int or archive.stat().st_size != record["bytes"]
            or _digest_file(archive) != record.get("sha256")):
        raise ValueError("metadata-and-results.zip: checksum or byte-count mismatch")
    entries = record.get("members")
    if (not isinstance(entries, list)
            or any(not isinstance(entry, dict) or not isinstance(entry.get("path"), str)
                   for entry in entries)):
        raise ValueError("Archive members must be a list of records with string paths")
    members = {}
    for entry in entries:
        name = entry["path"]
        if name in members:
            raise ValueError(f"Duplicate manifest member: {name}")
        members[name] = entry
    tables = {}
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate archive member names")
        for window in windows:
            name = f"results/{window}/03_replay/replay_overview.csv"
            if name not in members or name not in names:
                raise ValueError(f"Reference table missing from archive or manifest: {name}")
            contents = bundle.read(name)
            _check_record(members[name], contents, name)
            tables[window] = read_table(contents, f"reference {window}")
    return tables


def _numeric(value):
    return type(value) in (int, Decimal)


def _equal_number(reference, actual):
    # An integer in the published table is an exact quantity, never a tolerance
    # range. Decimal spellings such as 42.0 remain acceptable for that integer.
    if type(reference) is int:
        return reference == actual
    reference, actual = Decimal(reference), Decimal(actual)
    return abs(reference - actual) <= max(
        ABSOLUTE_TOLERANCE, RELATIVE_TOLERANCE * max(abs(reference), abs(actual)))


def value_differences(reference, actual, path):
    """Compare nested JSON without depending on object key order."""
    if _numeric(reference) and _numeric(actual):
        if not _equal_number(reference, actual):
            yield path, reference, actual, "numeric"
    elif type(reference) is not type(actual):
        yield path, reference, actual, "metadata"
    elif isinstance(reference, dict):
        for key in sorted(set(reference) | set(actual)):
            nested_path = f"{path}.{key}"
            if key not in reference or key not in actual:
                yield nested_path, reference.get(key, "<missing>"), actual.get(key, "<missing>"), "metadata"
            else:
                yield from value_differences(reference[key], actual[key], nested_path)
    elif isinstance(reference, list):
        if len(reference) != len(actual):
            yield f"{path}.length", len(reference), len(actual), "metadata"
        for index, (left, right) in enumerate(zip(reference, actual)):
            yield from value_differences(left, right, f"{path}[{index}]")
    elif reference != actual:
        yield path, reference, actual, "metadata"


@dataclass
class Comparison:
    window: str
    reference_cases: int
    actual_cases: int
    matched_cases: int = 0
    differing_cases: int = 0
    missing_cases: int = 0
    extra_cases: int = 0
    numeric_differences: int = 0
    metadata_differences: int = 0
    examples: list = field(default_factory=list)

    @property
    def matches(self):
        return not (self.differing_cases or self.missing_cases or self.extra_cases)

    def example(self, message):
        if len(self.examples) < MAX_DISPLAYED_DIFFERENCES:
            self.examples.append(message)


def _short(value):
    text = repr(value)
    return text if len(text) <= 160 else text[:157] + "..."


def compare_tables(window, reference, actual):
    reference_columns, reference_rows = reference
    actual_columns, actual_rows = actual
    if reference_columns != actual_columns:
        raise ValueError(f"{window}: CSV schema differs; missing columns: "
                         f"{sorted(reference_columns - actual_columns)}; "
                         f"extra columns: {sorted(actual_columns - reference_columns)}")
    outcome = Comparison(window, len(reference_rows), len(actual_rows))
    missing = set(reference_rows) - set(actual_rows)
    extra = set(actual_rows) - set(reference_rows)
    outcome.missing_cases, outcome.extra_cases = len(missing), len(extra)
    for key in sorted(missing):
        outcome.example(f"Missing case: {key}")
    for key in sorted(extra):
        outcome.example(f"Unexpected case: {key}")
    for key in sorted(set(reference_rows) & set(actual_rows)):
        changed = False
        for column in sorted(reference_columns):
            for path, expected, observed, kind in value_differences(
                    reference_rows[key][column], actual_rows[key][column], column):
                changed = True
                # This object describes cached cryptographic material. A new
                # signing run can change it without changing numerical results.
                if kind == "numeric" and column != "signature_workload_evidence":
                    outcome.numeric_differences += 1
                else:
                    outcome.metadata_differences += 1
                outcome.example(f"{key} {path}: reference={_short(expected)}, local={_short(observed)}")
        if changed:
            outcome.differing_cases += 1
        else:
            outcome.matched_cases += 1
    return outcome


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "Run the experiment's --validate-only checks first. Integer counts must "
        "match exactly; floating-point values use relative and absolute tolerances "
        "of 1e-9. Case and CSV column order do not matter. Fresh signing can change "
        "signature provenance and Falcon sizes; differences are reported, not waived."))
    parser.add_argument("--artifacts-dir", type=Path, required=True,
                        help="download directory containing artifact_manifest.json and metadata-and-results.zip")
    parser.add_argument("--results-dir", type=Path, default=ROOT / "results",
                        help="local results root (default: this repository's results/)")
    parser.add_argument("--window", choices=("daytime", "nighttime", "both"), default="both")
    args = parser.parse_args(argv)
    windows = ("daytime", "nighttime") if args.window == "both" else (args.window,)
    try:
        references = reference_tables(args.artifacts_dir, windows)
        outcomes = []
        for window in windows:
            path = args.results_dir / window / "03_replay" / "replay_overview.csv"
            current = read_table(path.read_bytes(), str(path))
            outcomes.append(compare_tables(window, references[window], current))
    except (OSError, ValueError, KeyError, TypeError, csv.Error, zipfile.BadZipFile) as error:
        print(f"Comparison could not complete: {error}", file=sys.stderr)
        return 2
    print("Integer counts: exact. Floating-point tolerances: rtol=1e-9, atol=1e-9.")
    for outcome in outcomes:
        print(f"{outcome.window}: {outcome.matched_cases}/{outcome.reference_cases} reference cases match; "
              f"{outcome.differing_cases} differ, {outcome.missing_cases} missing, {outcome.extra_cases} unexpected.")
        if not outcome.matches:
            print(f"  Numeric differences: {outcome.numeric_differences}; "
                  f"metadata/structure differences: {outcome.metadata_differences}.")
            for message in outcome.examples:
                print(f"  {message}")
            if len(outcome.examples) == MAX_DISPLAYED_DIFFERENCES:
                print(f"  At most {MAX_DISPLAYED_DIFFERENCES} differences are displayed per window.")
    if all(outcome.matches for outcome in outcomes):
        print(f"Agreement confirmed for {sum(o.reference_cases for o in outcomes)} replay cases, "
              "including table metadata. No files were changed.")
        return 0
    print("Agreement was not established. Fresh signing may change signature provenance "
          "even when numerical metrics match; Falcon signature sizes can also change numerical results.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
