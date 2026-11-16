"""Copy the outputs of tools/m14_runs.sh into examples/m14/ with their timing and memory.

Usage: python tools/m14_collect.py RUN_DIR
"""

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("setup-tampered", "eval-honest", "eval-tampered", "eval-wrong-statement", "eval-shared-statement")
SEEDS = {"setup-tampered": "tampered", "eval-honest": "honest", "eval-tampered": "tampered",
         "eval-wrong-statement": "statement-b", "eval-shared-statement": "shared-statement"}


def resources(text):
    wall = re.search(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([0-9:.]+)", text).group(1)
    parts = [float(p) for p in wall.split(":")]
    seconds = sum(p * 60 ** i for i, p in enumerate(reversed(parts)))
    rss = int(re.search(r"Maximum resident set size \(kbytes\): (\d+)", text).group(1))
    status = int(re.search(r"Exit status: (\d+)", text).group(1))
    return {"wall_seconds": round(seconds, 2), "max_rss_kib": rss, "exit_status": status}


def main():
    source = Path(sys.argv[1])
    out = ROOT / "examples" / "m14"
    out.mkdir(parents=True, exist_ok=True)
    binary = (source / "binary.sha256").read_text().split()[0]
    runs = {}
    for name in NAMES:
        record = json.loads((source / f"{name}.json").read_text(encoding="utf-8"))
        (out / f"{name}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8",
                                          newline="\n")
        seed = hashlib.sha256(f"bitvm-arena/m14/{SEEDS[name]}".encode()).hexdigest()[:16]
        runs[name] = {**resources((source / f"{name}.time").read_text()), "seed_hex": seed,
                      "verdict": record.get("verdict"), "m14_claim_seconds": round(record["seconds"], 2)}
    meta = {"tool": "m14-claim", "repository": "patrickdugan/garbled-snark-verifier", "commit": "04b6d3e",
            "binary_sha256": binary, "runs": runs}
    (out / "runs.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
