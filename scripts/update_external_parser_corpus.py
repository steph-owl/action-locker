#!/usr/bin/env python3
"""Fetch or verify the commit-pinned external workflow parser corpus.

Normal tests use ``--check`` and never access the network. Updating is an
explicit maintainer action that downloads exact source URLs, verifies their
reviewed SHA-256 digests, and records deterministic provenance.
"""

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "external_parser_corpus"
PROVENANCE = CORPUS / "PROVENANCE.json"
MAX_SOURCE_BYTES = 1024 * 1024

SOURCES = (
    {
        "file": "actions-checkout-test.yml",
        "repository": "actions/checkout",
        "commit": "e8d4307400f9427dba7cb98e488d6ab85f1cec5f",
        "path": ".github/workflows/test.yml",
        "sha256": "cc1cbdd36bae909c4f30f529505c860365156c3a9606b179729549631fc7d593",
        "license": "MIT",
        "license_url": "https://github.com/actions/checkout/blob/e8d4307400f9427dba7cb98e488d6ab85f1cec5f/LICENSE",
    },
    {
        "file": "pallets-flask-tests.yaml",
        "repository": "pallets/flask",
        "commit": "36e4a824f340fdee7ed50937ba8e7f6bc7d17f81",
        "path": ".github/workflows/tests.yaml",
        "sha256": "fefc4362b9823c261594a05c7919140c2e312eecee84c4dd10095dbdd00a514b",
        "license": "BSD-3-Clause",
        "license_url": "https://github.com/pallets/flask/blob/36e4a824f340fdee7ed50937ba8e7f6bc7d17f81/LICENSE.txt",
    },
    {
        "file": "astral-ruff-ci.yaml",
        "repository": "astral-sh/ruff",
        "commit": "c84e8eb7ba2ab68a7a61244d7411d0b855f90bd4",
        "path": ".github/workflows/ci.yaml",
        "sha256": "72d2160bdf686462e4c50e89555a13091fc9f03d82da7aa554f5f10d697795f0",
        "license": "MIT",
        "license_url": "https://github.com/astral-sh/ruff/blob/c84e8eb7ba2ab68a7a61244d7411d0b855f90bd4/LICENSE",
    },
    {
        "file": "python-cpython-build.yml",
        "repository": "python/cpython",
        "commit": "ba289460069fbdb5b035b48c5c0ba667d42a7ab9",
        "path": ".github/workflows/build.yml",
        "sha256": "a2b4bee27effc3f96f0540a7d63117d1111384e31e23138025b9c904e4ed26c8",
        "license": "Python-2.0",
        "license_url": "https://github.com/python/cpython/blob/ba289460069fbdb5b035b48c5c0ba667d42a7ab9/LICENSE",
    },
)


def source_url(source):
    return (
        "https://raw.githubusercontent.com/"
        f"{source['repository']}/{source['commit']}/{source['path']}"
    )


def expected_provenance():
    return {
        "schema_version": 1,
        "sources": [
            {**source, "source_url": source_url(source)} for source in SOURCES
        ],
    }


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_bytes(source, data):
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError(f"{source['file']} exceeds the corpus size limit")
    actual = digest(data)
    if actual != source["sha256"]:
        raise ValueError(
            f"{source['file']} SHA-256 mismatch: {actual}; "
            f"expected {source['sha256']}"
        )


def update():
    CORPUS.mkdir(parents=True, exist_ok=True)
    for source in SOURCES:
        request = urllib.request.Request(
            source_url(source), headers={"User-Agent": "action-locker-corpus"}
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(MAX_SOURCE_BYTES + 1)
        validate_bytes(source, data)
        (CORPUS / source["file"]).write_bytes(data)
    PROVENANCE.write_text(
        json.dumps(expected_provenance(), indent=2, sort_keys=True) + "\n"
    )
    check()


def check():
    if not PROVENANCE.is_file():
        raise ValueError("external corpus provenance is missing")
    if json.loads(PROVENANCE.read_text()) != expected_provenance():
        raise ValueError("external corpus provenance does not match the source pin")
    for source in SOURCES:
        path = CORPUS / source["file"]
        if not path.is_file():
            raise ValueError(f"external corpus fixture is missing: {source['file']}")
        validate_bytes(source, path.read_bytes())


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--update", action="store_true")
    args = parser.parse_args()
    try:
        update() if args.update else check()
    except (OSError, ValueError) as exc:
        print(f"external_parser_corpus: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
