"""Small stdlib-only PEP 517/660 builder for this pure-Python distribution.

No generic packaging framework: the package name/version and inclusion rules are
fixed here and checked by tests. Reproducible wheels include the shipped corpus.
"""

import base64
import csv
import gzip
import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NAME, VERSION = "bitvm_corpus", "0.1.0"
DIST = f"{NAME}-{VERSION}.dist-info"


def metadata():
    return (f"Metadata-Version: 2.1\nName: bitvm-corpus\nVersion: {VERSION}\n"
            "Summary: Corruption trajectories and control evaluations for BitVM DeFi\n"
            "Requires-Python: >=3.11\nLicense: MIT\nDescription-Content-Type: text/markdown\n\n"
            + (ROOT / "README.md").read_text(encoding="utf-8")).encode()


def _metadata_files():
    return {f"{DIST}/METADATA": metadata(),
            f"{DIST}/WHEEL": b"Wheel-Version: 1.0\nGenerator: bitvm-corpus-stdlib\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            f"{DIST}/entry_points.txt": b"[console_scripts]\nbitvm-corpus = bitvm_corpus.cli:main\n",
            f"{DIST}/LICENSE": (ROOT / "LICENSE").read_bytes()}


def _wheel(directory, editable=False):
    entries = _metadata_files()
    if editable:
        entries["bitvm_corpus.pth"] = (str(ROOT) + "\n").encode()
    else:
        for path in sorted((ROOT / NAME).rglob("*")):
            if path.is_file() and path.suffix in (".py", ".json") and "__pycache__" not in path.parts:
                entries[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, data in sorted(entries.items()):
        checksum = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow((name, "sha256=" + checksum, len(data)))
    writer.writerow((f"{DIST}/RECORD", "", ""))
    entries[f"{DIST}/RECORD"] = record.getvalue().encode()
    filename = f"{NAME}-{VERSION}-py3-none-any.whl"
    Path(directory).mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(Path(directory) / filename, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    return filename


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    return _wheel(wheel_directory)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    return _wheel(wheel_directory, editable=True)


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    for name, data in _metadata_files().items():
        path = Path(metadata_directory) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return DIST


prepare_metadata_for_build_editable = prepare_metadata_for_build_wheel


def get_requires_for_build_wheel(config_settings=None):
    return []


get_requires_for_build_editable = get_requires_for_build_wheel
get_requires_for_build_sdist = get_requires_for_build_wheel


def build_sdist(sdist_directory, config_settings=None):
    filename = f"{NAME}-{VERSION}.tar.gz"
    Path(sdist_directory).mkdir(parents=True, exist_ok=True)
    paths = [ROOT / name for name in ("pyproject.toml", "build_backend.py", "README.md", "LICENSE")]
    for directory in (NAME, "tests", "docs", "tools", "corpus", "examples"):
        paths += [p for p in (ROOT / directory).rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    with open(Path(sdist_directory) / filename, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for path in sorted(paths):
                    data = path.read_bytes()
                    info = tarfile.TarInfo(f"{NAME}-{VERSION}/{path.relative_to(ROOT).as_posix()}")
                    info.size, info.mode, info.mtime = len(data), 0o644, 0
                    archive.addfile(info, io.BytesIO(data))
    return filename
