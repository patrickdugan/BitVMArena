#!/bin/bash
# Record the M14-scale BitVM3 fixtures: one setup and four evaluations of the complete garbled
# final verifier (785,442,492 gates), with public fixture seeds.
#
#   M14_CLAIM=.../m14-claim FIXTURES=.../nova-bitvm3/m13/fixtures OUT=/tmp/m14 bash tools/m14_runs.sh
#
# m14-claim is nova-bitvm3/m14/e2e (bin m14-claim) of patrickdugan/garbled-snark-verifier at
# 04b6d3e, built with `cargo build --release`. Each run needs about 10 GB (setup) or more
# (evaluate: garbler and evaluator stream together). Then: python tools/m14_collect.py OUT.
set -u
: "${M14_CLAIM:?path to m14-claim}" "${FIXTURES:?path to nova-bitvm3/m13/fixtures}" "${OUT:?output directory}"
mkdir -p "$OUT"
A_ST=$FIXTURES/m16-statement.json; A_PR=$FIXTURES/m16-wrap-blake3-v2.bin; B_ST=$FIXTURES/c4-statement.json
# Seeds: first 8 bytes of sha256("bitvm-arena/m14/<name>").
run() {
  name=$1; shift
  echo "$(date -u +%FT%TZ) start $name"
  /usr/bin/time -v -o "$OUT/$name.time" "$M14_CLAIM" "$@" > "$OUT/$name.stdout" 2>&1
  echo "$(date -u +%FT%TZ) exit=$? $name"
}
run setup-tampered        setup    9844fd70de494d96 "$A_ST" "$OUT/setup-tampered.json"
run eval-honest           evaluate ff1f476222dbfe9f "$A_ST" "$A_PR" "$OUT/eval-honest.json"
run eval-tampered         evaluate 9844fd70de494d96 "$A_ST" "$A_PR" "$OUT/eval-tampered.json" 8635040
run eval-wrong-statement  evaluate 582c650d84926d21 "$B_ST" "$A_PR" "$OUT/eval-wrong-statement.json"
run eval-shared-statement evaluate e0565615e94b67bf "$A_ST" "$A_PR" "$OUT/eval-shared-statement.json"
sha256sum "$M14_CLAIM" > "$OUT/binary.sha256"
