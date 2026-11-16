"""Extract only verified Core test tools into work/; never install globally."""

import argparse
import hashlib
import json
import urllib.request
import zipfile
from pathlib import Path

VERSION = "31.2"
ARCHIVE_SHA256 = "dcae854f11791dbb8a69e391b709927e1b210b9c66ec164396a15816a46484d2"
URL = f"https://bitcoincore.org/bin/bitcoin-core-{VERSION}/bitcoin-{VERSION}-win64.zip"
ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=ROOT / f"work/toolchains/bitcoin-{VERSION}-win64.zip")
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    if args.download:
        args.archive.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(URL, timeout=30) as response, args.archive.open("wb") as out:
            total = 0
            while block := response.read(1_048_576):
                total += len(block)
                if total > 80_000_000:
                    raise RuntimeError("archive exceeds the pinned distribution size limit")
                out.write(block)
    archive_hash = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    if archive_hash != ARCHIVE_SHA256:
        raise RuntimeError("Core archive checksum mismatch; nothing extracted")
    target = ROOT / "work/toolchains/core-31.2"
    target.mkdir(parents=True, exist_ok=True)
    manifest = {"version": VERSION, "archive_url": URL, "archive_sha256": archive_hash, "binaries": {}}
    with zipfile.ZipFile(args.archive) as archive:
        for name in ("bitcoind.exe", "bitcoin-cli.exe"):
            data = archive.read(f"bitcoin-{VERSION}/bin/{name}")
            path = target / name
            path.write_bytes(data)
            manifest["binaries"][name] = hashlib.sha256(data).hexdigest()
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
