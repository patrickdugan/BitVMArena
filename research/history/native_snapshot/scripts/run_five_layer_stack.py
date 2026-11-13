from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bitvm_arena.compat import EvalMode
from bitvm_arena.attack import evaluate_attack_tasks
from bitvm_arena.dataset import build_task_instances
from bitvm_arena.definitions import COMBINATIONS
from bitvm_arena.mutations import build_mutation_catalog
from bitvm_arena.review import build_review_catalog
from bitvm_arena.rig import build_rig_catalog
from bitvm_arena.validation import build_validation_report
from bitvm_arena.wallet_preflight import build_preflight_catalog


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--outdir", default=str(ROOT / "data" / "generated"))
    parser.add_argument("--max-attack-tasks", type=int, default=None)
    parser.add_argument(
        "--combination-id",
        default=None,
        help="Optional exact combination id filter for attack/review iteration.",
    )
    parser.add_argument("--main-task-floor", type=float, default=0.75)
    parser.add_argument("--top-k", type=int, default=3)
    args = parser.parse_args()

    outdir = Path(args.outdir)

    rig_catalog = build_rig_catalog()
    preflight_catalog = build_preflight_catalog()
    mutation_catalog = build_mutation_catalog()
    review_catalog = build_review_catalog(COMBINATIONS)

    attack_tasks = build_task_instances(
        EvalMode.ATTACK,
        shuffle_seed=7,
    )
    if args.combination_id:
        attack_tasks = [
            task
            for task in attack_tasks
            if task.metadata.combination_id == args.combination_id
        ]
    if args.max_attack_tasks is not None:
        attack_tasks = attack_tasks[: args.max_attack_tasks]
    attack_report = evaluate_attack_tasks(
        attack_tasks,
        main_task_floor=args.main_task_floor,
        top_k=args.top_k,
    )
    validation_report = build_validation_report(
        attack_report["tasks"],
        main_task_floor=args.main_task_floor,
    )

    files = {
        "rig": "bitvm_rig_catalog.json",
        "preflight": "bitvm_wallet_preflight_catalog.json",
        "mutation": "bitvm_mutation_catalog.json",
        "review": "bitvm_review_catalog.json",
        "attack": "bitvm_attack_layer_report.json",
        "validation": "bitvm_validation_report.json",
    }

    write_json(outdir / files["rig"], rig_catalog)
    write_json(outdir / files["preflight"], preflight_catalog)
    write_json(outdir / files["mutation"], mutation_catalog)
    write_json(outdir / files["review"], review_catalog)
    write_json(outdir / files["attack"], attack_report)
    write_json(outdir / files["validation"], validation_report)

    manifest = {
        "files": files,
        "counts": {
            "rig": len(rig_catalog),
            "preflight": len(preflight_catalog),
            "mutation": len(mutation_catalog),
            "review": len(review_catalog),
            "attack_tasks": len(attack_report["tasks"]),
            "validation_regressions": len(validation_report["regression_cases"]),
        },
        "attack_summary": attack_report["summary"],
        "validation_summary": validation_report["summary"],
    }
    write_json(outdir / "five_layer_manifest.json", manifest)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
