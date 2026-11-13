# Original BitVM Arena code lineage

The original local Arena existed by May 2026 and remained available in the
recorded July 12 session. Its recovered Git log lists the following commits:

| Commit prefix | Recorded subject |
| --- | --- |
| `db7fd56` | Initial BitVM Arena with UTXORef research loop |
| `6ca5b6c` | Add BitVM Arena five-layer red-team stack |
| `547840a` | Add UTXORef TradeLayer send Arena red-team pass |
| `2cd6112` | Add TradeLayer stack Arena round two |
| `da9056f` | Add Shinigami ZK proof arena extension |

The recorded checkout was `C:\projects\BitVMArena`. An April directory inventory
also lists `C:\projects\BitVMArena.git`. These local paths identify useful places
to recover the original Git object database. A remote for that history was
unavailable during this recovery.

## What was recovered

`native_snapshot/` contains nine files reconstructed from recorded PowerShell
reads. Five complete Python files cover the rig, review, attack and validation
layers plus their runner. The two design documents and `pyproject.toml` were
also read in full. `README.md` came from a command bounded to 240 lines, so its
completeness remains marked separately.

The recorded reads occurred at checkout HEAD prefix `da9056f`. Command headers
were removed; file boundaries were identified using the original command and
the source syntax. Line endings were normalized to LF.
[`provenance.json`](provenance.json) lists the source record line for each file
and the SHA256 digest of each reconstruction. The original Git blob hashes
were unavailable. All five Python files parse successfully.

The source rollout also shows `setting.py`, `scorer.py`, `dataset.py`,
`models.py`, `wallet_preflight.py`, a Shinigami extension and generated honest
and attack JSONL files. Their complete source has yet to be recovered. Reads
of the Shinigami runner, mutations and preflight were truncated, so those
fragments are excluded from this snapshot.

## Relationship to the rebuilt Arena

The historical setting presented structured protocol-review tasks. Its attack
layer searched for trajectories that retained a loophole while maintaining a
review-task score. The recovered modules preserve those original contracts
for future migration and for comparison with the rebuilt simulator.

The active package lives in `src/bitvm_arena`. This historical snapshot has
missing dependencies and remains outside that package and its test discovery.
Its recorded benchmark counts describe the original scoring model. Fresh
consensus evidence requires an executable verifier and reproduced receipts.

The history establishes a working local code lineage through July 12. The
available records leave the reported August loss or migration unresolved.

## Independent references

The UTXO-Ref maintenance handoff dated May 3 records `2cd6112` as the related
Arena commit. HybridTRMLDT's inventory also records the local checkout and the
Shinigami runner:

- [HybridTRMLDT inventory at `e412e841`](https://github.com/MoralityLabAI/HybridTRMLDT/blob/e412e84131548e5b0c7534bd6f440a9089962b73/data/benchmarks/local_game_env_inventory.json)
- [HybridTRMLDT synthetic control-profile proxy](https://github.com/MoralityLabAI/HybridTRMLDT/blob/e412e84131548e5b0c7534bd6f440a9089962b73/research_gym/envs/control_tasks.py)

Only project-specific source reads are included here. The complete historical
rollout stays outside the repository.
