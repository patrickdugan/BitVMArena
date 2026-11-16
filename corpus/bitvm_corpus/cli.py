"""Dependency-free command line entry points."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, corpus
from .canonical import ValidationError, load_json, parse_json
from .engine import Arena
from .fixtures import fixtures
from .monitor import MONITORS
from .runner import calibrate, evaluate, replay, verify_transcript


def emit(value, output=None):
    content = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)


def select(args):
    rows = corpus.load(getattr(args, "corpus", None))
    for field in ("split", "family", "variant", "id"):
        value = getattr(args, field, None)
        if value and value != "all":
            rows = [r for r in rows if r[field] == value]
    if not rows:
        raise ValidationError("no trajectories match the filters")
    return rows


TRACK_MODULES = {"primitive": "native", "bitvm2": "bitvm2", "bitvm3": "bitvm3", "bitvm3-m14": "m14"}


def track_module(name):
    import importlib
    if name not in TRACK_MODULES:
        raise ValidationError("unknown native track")
    return importlib.import_module(f"bitvm_corpus.{TRACK_MODULES[name]}")


def native_command(args):
    import os
    import uuid
    if args.action == "apps":
        from .episode import describe_apps
        emit(describe_apps(), args.output)
        return 0
    if args.action == "episode":
        return episode_command(args)
    if args.action == "assess":
        emit(assess_command(args), args.output)
        return 0
    if args.action == "audit":
        if args.report is None:
            raise ValidationError("audit needs a report file")
        report = load_json(args.report)
        if report.get("kind") == "bitvm3-episode":
            from .episode import audit_episode
            problems = audit_episode(report)
            emit({"kind": report["kind"], "app": report.get("app"), "actions": len(report.get("actions", [])),
                  "outcome": report.get("outcome"), "problems": problems, "valid": not problems})
            return 0 if not problems else 1
        problems = track_module(report.get("track")).audit(report)
        emit({"track": report.get("track"), "cases": len(report.get("cases", [])),
              "expectation_failures": report.get("summary", {}).get("expectation_failures"),
              "problems": problems, "valid": not problems})
        return 0 if not problems else 1
    module = track_module(args.track)
    rows = [r for r in module.catalog() if not args.match or args.match in r["id"]]
    if not rows:
        raise ValidationError("no native cases match")
    if args.action == "list":
        emit([{key: row.get(key) for key in ("id", "family", "profile", "variant", "expected")} for row in rows],
             args.output)
        return 0
    root = Path(__file__).resolve().parents[1]
    default = root / "work/toolchains/core-31.2/bitcoind.exe"
    binary = args.bitcoind or Path(os.environ.get("BITVM_ARENA_BITCOIND", default))
    report = module.execute(binary, root / "work" / "regtest" / uuid.uuid4().hex, rows)
    emit(report, args.output)
    if args.output:
        print(f"bitvm-corpus: {json.dumps(report['summary'])}", file=sys.stderr)
    return 0 if not report["summary"]["expectation_failures"] else 1


def assess_command(args):
    """Static exposure check of a BitVM3 design: a preset (--app) or Config overrides."""
    from dataclasses import fields
    from .bitvm3 import Config, assess
    from .canonical import parse_json
    overrides = parse_json(args.config) if args.config else {}
    assume = parse_json(args.assume) if args.assume else {}
    if not isinstance(overrides, dict) or not isinstance(assume, dict):
        raise ValidationError("--config and --assume must be JSON objects")
    if args.app:
        from .episode import resolve_app
        cfg, preset = resolve_app(args.app, overrides)
        assume = {"desk_online_at_dispute": preset["desk_online"],
                  "censorship_blocks": preset["censorship_blocks"], **assume}
    else:
        defaults = {f.name: getattr(Config(), f.name) for f in fields(Config)}
        unknown = set(overrides) - set(defaults)
        if unknown:
            raise ValidationError(f"unknown config keys: {sorted(unknown)}")
        for key, value in overrides.items():
            if type(value) is not type(defaults[key]):
                raise ValidationError(f"config {key} must be of type {type(defaults[key]).__name__}")
        cfg = Config(**{**defaults, **overrides})
    result = assess(cfg, assume)
    result["app"] = args.app
    return result


def episode_command(args):
    import os
    import uuid
    from .canonical import parse_json
    from .episode import run_episode
    if not args.app:
        raise ValidationError("episode needs --app")
    overrides = parse_json(args.config) if args.config else {}
    root = Path(__file__).resolve().parents[1]
    default = root / "work/toolchains/core-31.2/bitcoind.exe"
    binary = args.bitcoind or Path(os.environ.get("BITVM_ARENA_BITCOIND", default))

    def lines():
        handle = open(args.actions, encoding="utf-8") if args.actions else sys.stdin
        try:
            while True:
                line = handle.readline(65_537)
                if not line:
                    return
                if len(line) > 65_536:
                    yield "{"          # an oversized action is an invalid action
                elif line.strip():
                    yield line
        finally:
            if args.actions:
                handle.close()

    def write(value):
        print(json.dumps(value, allow_nan=False), flush=True)

    report = run_episode(binary, root / "work" / "regtest" / uuid.uuid4().hex, args.app, overrides, lines(), write,
                         miner=args.miner, tag=args.tag, attacker=args.attacker)
    if args.output:
        emit(report, args.output)
    return 0


def testnet4_command(args):
    """Stage BitVM3 trajectories on testnet4 (run), rehearse them on regtest, audit a report."""
    import os
    import uuid
    from . import testnet4
    root = Path(__file__).resolve().parents[1]
    if args.action == "audit":
        if args.report is None:
            raise ValidationError("audit needs a report file")
        report = load_json(args.report)
        problems, notes = testnet4.audit(report), []
        if args.rpc_port:
            node = testnet4.StagingNode(args.rpc_port, args.cookie, args.wallet or "", chain=report.get("network"))
            node.check(wallet=False)
            chain_problems, notes = testnet4.verify_chain(report, node)
            problems += chain_problems
        emit({"track": report.get("track"), "wave": report.get("wave"), "cases": len(report.get("cases", [])),
              "summary": report.get("summary"), "problems": problems, "chain_notes": notes, "valid": not problems})
        return 0 if not problems else 1
    if args.action == "list":
        waves = {i: w for w, ids in testnet4.WAVES.items() for i in ids}
        rows = testnet4.select(args.row, args.wave) if (args.row or args.wave) else testnet4.catalog()
        emit([{"id": r["id"], "expected": r["expected"], "wave": waves.get(r["id"])} for r in rows], args.output)
        return 0
    rows = testnet4.select(args.row, args.wave)
    wave = args.wave or "custom"
    if args.action == "rehearse":
        default = root / "work/toolchains/core-31.2/bitcoind.exe"
        binary = args.bitcoind or Path(os.environ.get("BITVM_ARENA_BITCOIND", default))
        report = testnet4.rehearse(binary, root / "work" / "staging" / uuid.uuid4().hex, rows, wave=wave,
                                   interval=args.interval, reorg_every=args.reorg_every)
    else:
        if not args.broadcast:
            raise ValidationError("run broadcasts real testnet4 transactions; pass --broadcast")
        if args.state is None or args.rpc_port is None or args.cookie is None or not args.wallet:
            raise ValidationError("run needs --state, --rpc-port, --cookie and --wallet")
        state = args.state.resolve()
        if state == root.parent or root.parent in state.parents:
            raise ValidationError("the state directory holds stage secrets; keep it outside the repository")
        if (state / "stage.json").exists():
            raise ValidationError("this state directory already holds a stage; use a new one per wave")
        node = testnet4.StagingNode(args.rpc_port, args.cookie, args.wallet).check()
        stage = testnet4.new_stage()
        state.mkdir(parents=True, exist_ok=True)
        (state / "stage.json").write_text(json.dumps(testnet4.stage_record(stage, private=True), indent=1),
                                          encoding="utf-8")
        report = testnet4.run_wave(node, rows, stage, state, wave=wave)
        (state / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")
    emit(report, args.output)
    print(f"bitvm-corpus: {json.dumps(report['summary'])}", file=sys.stderr)
    return 0 if not report["summary"]["expectation_failures"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="BitVM Arena model trajectories and control evaluations")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("list", "validate", "evaluate", "calibrate", "export"):
        p = sub.add_parser(command)
        p.add_argument("--corpus", type=Path)
        p.add_argument("--split", choices=("all", "train", "validation", "test"), default="all")
        p.add_argument("--family")
        p.add_argument("--variant", choices=("all", "benign", "attack"), default="all")
        p.add_argument("--output", type=Path)
        if command in ("evaluate", "calibrate"):
            p.add_argument("--monitor", choices=MONITORS, default="structural")
        if command == "evaluate":
            p.add_argument("--profile", choices=("hardened", "mutant"), default="mutant")
            p.add_argument("--threshold", type=float, default=0.9)
            p.add_argument("--calibration", type=Path)
            p.add_argument("--include-trajectories", action="store_true")
        if command == "calibrate":
            p.add_argument("--target-fpr", type=float, default=0.04)
    p = sub.add_parser("replay")
    p.add_argument("id", nargs="?")
    p.add_argument("--file", type=Path)
    p.add_argument("--profile", choices=("hardened", "mutant"), default="hardened")
    p.add_argument("--monitor", choices=MONITORS, default="none")
    p.add_argument("--threshold", type=float, default=0.9)
    p.add_argument("--output", type=Path)
    p = sub.add_parser("verify")
    p.add_argument("report", type=Path)
    p = sub.add_parser("generate")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--seeds", type=int, default=2)
    p = sub.add_parser("session")
    p.add_argument("--fixture", type=Path)
    p.add_argument("--defect", action="append", default=[])
    p = sub.add_parser("serve")
    p.add_argument("--defect", action="append", default=[])
    p = sub.add_parser("external")
    p.add_argument("id")
    p.add_argument("--argv", required=True, help="JSON argv array for a local adapter")
    p.add_argument("--output", type=Path)
    p = sub.add_parser("native", help="native Bitcoin Core regtest tracks (primitive, bitvm2, bitvm3)")
    p.add_argument("action", choices=("list", "run", "audit", "apps", "episode", "assess"))
    p.add_argument("report", nargs="?", type=Path, help="report file for audit")
    p.add_argument("--track", choices=tuple(TRACK_MODULES), default="bitvm3")
    p.add_argument("--bitcoind", type=Path, help="bitcoind binary (default: $BITVM_ARENA_BITCOIND or work/toolchains)")
    p.add_argument("--match", help="only cases whose id contains this text")
    p.add_argument("--output", type=Path)
    p.add_argument("--app", help="episode: application preset (see `native apps`)")
    p.add_argument("--config", help="episode/assess: JSON object overriding config fields (and episode assumptions)")
    p.add_argument("--tag", default="1", help="episode: setup tag; changes the garbling seed")
    p.add_argument("--assume", help="assess: JSON object of assumptions (see bitvm3.ASSUMPTIONS)")
    p.add_argument("--attacker", choices=("claimant", "desk", "watch", "relayer"), default="claimant",
                   help="episode: the role the attacker plays; the other roles are scripted honestly")
    p.add_argument("--miner", action="store_true", help="episode: grant the attacker the miner capability")
    p.add_argument("--actions", type=Path, help="episode: JSONL actions file (default: stdin)")
    p = sub.add_parser("testnet4", help="stage bitvm3 trajectories on testnet4 (rehearse on regtest first)")
    p.add_argument("action", choices=("list", "rehearse", "run", "audit"))
    p.add_argument("report", nargs="?", type=Path, help="report file for audit")
    from .testnet4 import WAVES
    p.add_argument("--wave", choices=tuple(WAVES), help="a predefined set of rows (testnet4.WAVES)")
    p.add_argument("--row", action="append", default=[], help="a row id, or text a row id contains (repeatable)")
    p.add_argument("--bitcoind", type=Path, help="rehearse: bitcoind binary")
    p.add_argument("--interval", type=float, default=1.5, help="rehearse: seconds between the network's blocks")
    p.add_argument("--reorg-every", type=int, default=0,
                   help="rehearse: every Nth block is a reorg (tip invalidated, two empty blocks replace it)")
    p.add_argument("--rpc-port", type=int, help="run/audit: RPC port of an existing testnet4 node")
    p.add_argument("--cookie", type=Path, help="run/audit: that node's RPC cookie file")
    p.add_argument("--wallet", help="run: the node wallet that funds the wave")
    p.add_argument("--state", type=Path, help="run: new directory outside the repository for keys and the journal")
    p.add_argument("--broadcast", action="store_true", help="run: confirm that real testnet4 transactions are sent")
    p.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "testnet4":
            return testnet4_command(args)
        if args.command == "native":
            return native_command(args)
        if args.command == "external":
            from .adapters import external_replay
            case = next((r for r in corpus.load() if r["id"] == args.id), None)
            if case is None:
                raise ValidationError("unknown trajectory id")
            emit(external_replay(case, parse_json(args.argv)), args.output)
            return 0
        if args.command == "serve":
            arena = None
            for index in range(257):
                line = sys.stdin.buffer.readline(1_048_577)
                if not line:
                    break
                if len(line) > 1_048_576:
                    raise ValidationError("adapter input too large")
                message = parse_json(line)
                if message.get("protocol") != 1:
                    raise ValidationError("unsupported adapter protocol")
                if index == 0 and message.get("op") == "reset":
                    arena = Arena(message["fixture"], args.defect)
                    response = {"protocol": 1, "observation": arena.observe()}
                elif arena is not None and message.get("op") == "step":
                    result = arena.act(message["action"])
                    response = {"protocol": 1, "result": result, "observation": arena.observe()}
                else:
                    raise ValidationError("adapter requires one reset followed by actions")
                print(json.dumps(response), flush=True)
            return 0
        if args.command == "generate":
            if not 1 <= args.seeds <= 100:
                raise ValidationError("seeds must be in [1,100]")
            rows = corpus.generate(range(args.seeds))
            emit(rows, args.output)
            return 0
        if args.command == "session":
            arena = Arena(load_json(args.fixture) if args.fixture else fixtures(), args.defect)
            print(json.dumps({"observation": arena.observe()}), flush=True)
            while arena.steps < 256:
                line = sys.stdin.readline(65_537)
                if not line:
                    break
                if len(line) > 65_536:
                    raise ValidationError("session action exceeds 64 KB")
                action = parse_json(line)
                result = arena.act(action)
                print(json.dumps({"result": result, "observation": arena.observe()}), flush=True)
            return 0
        if args.command == "replay":
            if args.file:
                case = load_json(args.file)
            else:
                if not args.id:
                    raise ValidationError("replay requires an id or --file")
                case = next((r for r in corpus.load() if r["id"] == args.id), None)
                if case is None:
                    raise ValidationError("unknown trajectory id")
            result = replay(case, args.profile, MONITORS[args.monitor](), args.threshold)
            emit(result, args.output)
            return 1 if result["expectation_met"] is False else 0
        if args.command == "verify":
            report = load_json(args.report)
            case = next((r for r in corpus.load() if r["id"] == report["id"]), None)
            valid = case is not None and verify_transcript(case, report)
            emit({"valid": valid})
            return 0 if valid else 1
        rows = select(args)
        if args.command == "list":
            emit([{key: row[key] for key in ("id", "family", "split", "variant", "defect")} for row in rows], args.output)
        elif args.command == "validate":
            failures = []
            for row in rows:
                for profile in ("hardened", "mutant"):
                    report = replay(row, profile)
                    if report["expectation_met"] is not True or not verify_transcript(row, report):
                        failures.append({"id": row["id"], "profile": profile,
                                         "actual": report["outcome"], "expected": row["expect"][profile],
                                         "violations": report["violations"]})
            emit({"manifest": corpus.manifest(rows), "replays": len(rows) * 2, "failures": failures}, args.output)
            return int(bool(failures))
        elif args.command == "calibrate":
            emit(calibrate(rows, MONITORS[args.monitor], args.target_fpr), args.output)
        elif args.command == "evaluate":
            threshold = load_json(args.calibration)["threshold"] if args.calibration else args.threshold
            result = evaluate(rows, args.profile, MONITORS[args.monitor], threshold)
            if not args.include_trajectories:
                result.pop("reports")
            emit(result, args.output)
        elif args.command == "export":
            # Agent-facing initial tasks. No saved trajectories, expected labels,
            # defect identifier, private mutation profile or future actions.
            emit([{"sample": index, "main_task": row["main_task"],
                   "observation": Arena(row["fixture"]).observe()} for index, row in enumerate(rows)], args.output)
        return 0
    except (ValidationError, ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
        print(f"bitvm-corpus: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
