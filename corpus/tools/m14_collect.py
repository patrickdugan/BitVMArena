"""Copy the outputs of tools/m14_runs.sh into examples/m14/ with their timing and memory.

Usage:
  python tools/m14_collect.py RUN_DIR             a local run directory
  python tools/m14_collect.py --annotate RUN_DIR  print the runs as GitHub annotations (the
                                                  "Record M14 runs" workflow does this)
  python tools/m14_collect.py --ci RUN_ID         collect from that workflow run's annotations

The verifier revision is the one pinned in tools/m14_record.json. Job logs and artifacts of a
public repository need a sign-in; annotations do not, and a run record is about 1 kB, so the
workflow publishes each record as one annotation and `--ci` reads them back.
"""

import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT / "tools" / "m14_record.json").read_text(encoding="utf-8"))
ARENA = "patrickdugan/BitVMArena"
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


def read_directory(source):
    """(binary sha256, {name: (record, resources)}) of a tools/m14_runs.sh output directory."""
    binary = (source / "binary.sha256").read_text().split()[0]
    runs = {}
    for name in NAMES:
        record = json.loads((source / f"{name}.json").read_text(encoding="utf-8"))
        runs[name] = (record, resources((source / f"{name}.time").read_text()))
    return binary, runs


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def annotate(source):
    """One notice per run and one for the binary. Fails if a run did not exit 0."""
    binary, runs = read_directory(source)
    failed = [name for name, (_, used) in runs.items() if used["exit_status"] != 0]
    if failed:
        print(f"::error title=m14-record::runs that did not exit 0: {', '.join(failed)}")
        return 1
    print(f"::notice title=m14-binary::{compact({'binary_sha256': binary, 'commit': PIN['commit']})}")
    for name, (record, used) in runs.items():
        print(f"::notice title=m14-run {name}::{compact({'record': record, 'resources': used})}")
    return 0


def get(path):
    request = urllib.request.Request(f"https://api.github.com/repos/{ARENA}/{path}",
                                     headers={"Accept": "application/vnd.github+json", "User-Agent": "m14-collect"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def read_ci(run_id):
    """The same as read_directory, from the annotations of a "Record M14 runs" workflow run."""
    run = get(f"actions/runs/{run_id}")
    if run["conclusion"] != "success":
        raise SystemExit(f"workflow run {run_id} is {run['status']}/{run['conclusion']}")
    notes = {}
    for job in get(f"actions/runs/{run_id}/jobs?per_page=50")["jobs"]:
        for a in get(f"check-runs/{job['id']}/annotations?per_page=100"):
            if (a.get("title") or "").startswith("m14-"):
                notes[a["title"]] = json.loads(a["message"])
    binary = notes["m14-binary"]
    if binary["commit"] != PIN["commit"]:
        raise SystemExit(f"run {run_id} recorded {binary['commit']}, tools/m14_record.json pins {PIN['commit']}")
    runs = {name: (notes[f"m14-run {name}"]["record"], notes[f"m14-run {name}"]["resources"]) for name in NAMES}
    where = {"where": "github-actions", "workflow": "Record M14 runs", "run_id": int(run_id),
             "url": run["html_url"], "arena_commit": run["head_sha"]}
    return binary["binary_sha256"], runs, where


def write(binary, runs, where):
    out = ROOT / "examples" / "m14"
    out.mkdir(parents=True, exist_ok=True)
    summary = {}
    for name in NAMES:
        record, used = runs[name]
        (out / f"{name}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8",
                                          newline="\n")
        seed = hashlib.sha256(f"bitvm-arena/m14/{SEEDS[name]}".encode()).hexdigest()[:16]
        summary[name] = {**used, "seed_hex": seed, "verdict": record.get("verdict"),
                         "m14_claim_seconds": round(record["seconds"], 2)}
    meta = {"tool": "m14-claim", "repository": PIN["repository"], "commit": PIN["commit"][:7],
            "binary_sha256": binary, "recorded": where, "runs": summary}
    (out / "runs.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(meta, indent=2))


def main():
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "--annotate":
        return annotate(Path(args[1]))
    if len(args) == 2 and args[0] == "--ci":
        write(*read_ci(args[1]))
    elif len(args) == 1 and not args[0].startswith("--"):
        binary, runs = read_directory(Path(args[0]))
        write(binary, runs, {"where": "local"})
    else:
        raise SystemExit(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
