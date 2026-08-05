#!/usr/bin/env python3
"""Reproducibly vendor Action Locker's pinned pure-Python YAML closure.

Usage:
    python3 scripts/vendor_ruamel.py /path/to/ruamel_yaml-0.19.1-py3-none-any.whl
    python3 scripts/vendor_ruamel.py --check

The wheel must be obtained from the URL recorded in PROVENANCE.json. This
script refuses a different digest, validates package metadata, extracts only
the pure-Python `ruamel/yaml` package, copies its MIT license/metadata, and
writes a deterministic SHA-256 manifest. It never downloads anything.
"""

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "ruamel.yaml"
VERSION = "0.19.1"
WHEEL = "ruamel_yaml-0.19.1-py3-none-any.whl"
WHEEL_SHA256 = "27592957fedf6e0b62f281e96effd28043345e0e66001f97683aa9a40c667c93"
WHEEL_URL = (
    "https://files.pythonhosted.org/packages/b8/0c/"
    "51f6841f1d84f404f92463fc2b1ba0da357ca1e3db6b7fbda26956c3b82a/"
    + WHEEL
)
VENDOR_ROOT = ROOT / "_vendor" / "ruamel" / "yaml"
NOTICE_ROOT = ROOT / "third_party" / "ruamel.yaml"
MANIFEST = NOTICE_ROOT / "MANIFEST.sha256"
PROVENANCE = NOTICE_ROOT / "PROVENANCE.json"
EMBEDDED_METADATA = VENDOR_ROOT / "UPSTREAM_METADATA.action-locker"
EMBEDDED_PROVENANCE = VENDOR_ROOT / "PROVENANCE.action-locker.json"
EMBEDDED_MANIFEST = VENDOR_ROOT / "MANIFEST.action-locker.sha256"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_paths():
    paths = sorted(
        path for path in VENDOR_ROOT.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
        and path != EMBEDDED_MANIFEST
    )
    return sorted(paths, key=lambda path: path.relative_to(ROOT).as_posix())


def manifest_text():
    return "".join(
        f"{sha256_file(path)}  {path.relative_to(ROOT).as_posix()}\n"
        for path in manifest_paths()
    )


def validate_metadata(raw):
    metadata = Parser().parsestr(raw.decode("utf-8"))
    if metadata["Name"] != PACKAGE or metadata["Version"] != VERSION:
        raise ValueError(
            f"wheel metadata is {metadata['Name']} {metadata['Version']}, "
            f"expected {PACKAGE} {VERSION}"
        )
    runtime_requires = [
        value for value in metadata.get_all("Requires-Dist", [])
        if "extra ==" not in value
    ]
    if runtime_requires:
        raise ValueError(f"unexpected default runtime dependencies: {runtime_requires}")


def vendor(wheel_path):
    wheel_path = Path(wheel_path)
    if wheel_path.name != WHEEL:
        raise ValueError(f"wheel filename must be {WHEEL}")
    actual = sha256_file(wheel_path)
    if actual != WHEEL_SHA256:
        raise ValueError(f"wheel SHA-256 mismatch: {actual}")

    dist_prefix = f"ruamel_yaml-{VERSION}.dist-info/"
    with zipfile.ZipFile(wheel_path) as archive:
        metadata_name = dist_prefix + "METADATA"
        license_name = dist_prefix + "licenses/LICENSE"
        metadata = archive.read(metadata_name)
        license_text = archive.read(license_name)
        validate_metadata(metadata)
        members = []
        for name in archive.namelist():
            pure = PurePosixPath(name)
            if not name.startswith("ruamel/yaml/") or name.endswith("/"):
                continue
            if "__pycache__" in pure.parts or pure.suffix == ".pyc":
                continue
            members.append(name)
        if "ruamel/yaml/__init__.py" not in members:
            raise ValueError("wheel does not contain ruamel/yaml/__init__.py")

        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            staged = Path(tmpdir) / "yaml"
            for name in sorted(members):
                relative = PurePosixPath(name).relative_to("ruamel/yaml")
                destination = staged.joinpath(*relative.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(name))
            if VENDOR_ROOT.exists():
                shutil.rmtree(VENDOR_ROOT)
            VENDOR_ROOT.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(staged, VENDOR_ROOT)

    # Keep the upstream license inside the importable package as well as in
    # third_party so every distributed wheel/zipapp carries its attribution.
    (VENDOR_ROOT / "LICENSE.action-locker-vendored").write_bytes(license_text)

    NOTICE_ROOT.mkdir(parents=True, exist_ok=True)
    (NOTICE_ROOT / "LICENSE").write_bytes(license_text)
    (NOTICE_ROOT / "METADATA").write_bytes(metadata)
    provenance = {
        "package": PACKAGE,
        "version": VERSION,
        "source_artifact": WHEEL,
        "source_sha256": WHEEL_SHA256,
        "source_url": WHEEL_URL,
        "license": "MIT",
        "runtime_dependencies": [],
        "update_command": f"python3 scripts/vendor_ruamel.py /path/to/{WHEEL}",
    }
    provenance_text = json.dumps(provenance, indent=2, sort_keys=True) + "\n"
    PROVENANCE.write_text(provenance_text)
    EMBEDDED_METADATA.write_bytes(metadata)
    EMBEDDED_PROVENANCE.write_text(provenance_text)
    manifest = manifest_text()
    MANIFEST.write_text(manifest)
    EMBEDDED_MANIFEST.write_text(manifest)
    check()


def check():
    if not PROVENANCE.is_file() or not MANIFEST.is_file():
        raise ValueError("vendored parser provenance or manifest is missing")
    provenance = json.loads(PROVENANCE.read_text())
    expected_provenance = {
        "package": PACKAGE,
        "version": VERSION,
        "source_artifact": WHEEL,
        "source_sha256": WHEEL_SHA256,
        "source_url": WHEEL_URL,
        "license": "MIT",
        "runtime_dependencies": [],
        "update_command": f"python3 scripts/vendor_ruamel.py /path/to/{WHEEL}",
    }
    if provenance != expected_provenance:
        raise ValueError("PROVENANCE.json does not match the update script pin")
    manifest = manifest_text()
    if MANIFEST.read_text() != manifest:
        raise ValueError("vendored parser manifest is stale or a file was modified")
    if EMBEDDED_METADATA.read_bytes() != (NOTICE_ROOT / "METADATA").read_bytes():
        raise ValueError("artifact-embedded upstream metadata is stale")
    if (VENDOR_ROOT / "LICENSE.action-locker-vendored").read_bytes() != (
        NOTICE_ROOT / "LICENSE"
    ).read_bytes():
        raise ValueError("artifact-embedded upstream license is stale")
    if EMBEDDED_PROVENANCE.read_text() != PROVENANCE.read_text():
        raise ValueError("artifact-embedded provenance is stale")
    if EMBEDDED_MANIFEST.read_text() != manifest:
        raise ValueError("artifact-embedded manifest is stale")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", nargs="?", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        if args.check:
            if args.wheel is not None:
                parser.error("--check does not accept a wheel")
            check()
        elif args.wheel is None:
            parser.error("provide the pinned wheel or use --check")
        else:
            vendor(args.wheel)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        print(f"vendor_ruamel: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
