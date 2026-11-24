"""Print the detection-versus-payload tables of docs/SETUP.md from a saved stego study.

    python tools/setup_study_table.py examples/setup/stego-monitor.json
"""

import json
import sys

COLUMNS = (1, 2, 3, 8, 32, 128, 512)
NAMES = {"style_session": "style, per session", "style_message": "style, per message",
         "style_adaptive": "style, session then message then slots", "format_slots": "`format` slots",
         "case_slots": "`case` slots", "order_slots": "`order` slots", "salt_keyed": "`salt`, keyed",
         "salt_plain": "`salt`, plain (zero-padded)"}


def main(path):
    study = json.load(open(path, encoding="utf-8"))
    rows = {(r["regime"], r["channel"], r["payload_bits"]): r for r in study["rows"]}
    for regime in ("canonical", "heterogeneous"):
        honest = rows[(regime, "honest", 0)]
        print(f"**{regime}** (honest false-positive rate, any monitor: {honest['false_positive_rate_any']:.2f})\n")
        print("| Channel | " + " | ".join(f"{c} bit{'s' if c > 1 else ''}" for c in COLUMNS)
              + " | Capacity | Decoded | Survives canonical hub |")
        print("| --- | " + " | ".join("---:" for _ in COLUMNS) + " | ---: | ---: | --- |")
        for channel, name in NAMES.items():
            cells, last = [], None
            for c in COLUMNS:
                r = rows.get((regime, channel, c))
                cells.append("-" if r is None else f"{r['detection_any']:.2f}")
                last = r or last
            sizes = [r for (g, ch, _), r in rows.items() if g == regime and ch == channel]
            decoded = min(r["decoded"] for r in sizes)
            top = max(sizes, key=lambda r: r["payload_bits"])
            survive = top["survives_canonical_hub"] - top["chance_agreement"]
            print(f"| {name} | " + " | ".join(cells) + f" | {last['capacity_bits']} | {decoded:.2f} | "
                  f"{'yes' if survive > 0.5 else 'no'} |")
        print()
    k = study["klepto"]
    print(f"Kleptographic nonce: {k['keys_recovered']} of {k['signatures']} keys recovered from one signature each; "
          f"AUROC of bit bias {k['auroc']['bit_bias']:.2f}, of zero bytes {k['auroc']['zero_bytes']:.2f}; "
          f"nonce reuse in honest signatures {k['nonce_reuse']['honest']}, in klepto signatures "
          f"{k['nonce_reuse']['klepto']}.")


if __name__ == "__main__":
    main(sys.argv[1])
