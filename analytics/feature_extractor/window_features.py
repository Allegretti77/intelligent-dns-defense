#!/usr/bin/env python3
"""Features de janela DESLIZANTE por origem, sobre o stream do Zeek.

Para cada evento Zeek, calcula sobre a janela [t-X, t] da mesma source_ip:
win_count, win_qps, win_unique_qnames, win_any_ratio, win_nxdomain_ratio,
win_txt_ratio. Anexa essas colunas a cada linha de feature (por event_id).
Eventos nao-Zeek passam adiante com win_* = null (usa-se uma regua so, o Zeek,
para nao contar a mesma transacao tres vezes).

Entradas: eventos canonicos (timestamp/source_ip/query) + arquivo de features
(para anexar as colunas). Saida: features enriquecidas (JSON lines).
"""
import argparse, json, sys
from collections import defaultdict
from datetime import datetime

QTYPE_CANON = {"*": "ANY", "255": "ANY", "ANY": "ANY"}
def canon(qt): return QTYPE_CANON.get(qt, qt) if qt else qt
def to_epoch(ts): return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()

WIN_KEYS = ("win_count","win_qps","win_unique_qnames","win_any_ratio","win_nxdomain_ratio","win_txt_ratio")

def compute_windows(zeek, window):
    by_src = defaultdict(list)
    for e in zeek:
        by_src[e["src"]].append(e)
    out = {}
    for evs in by_src.values():
        evs.sort(key=lambda x: x["t"])
        lo = 0
        for hi in range(len(evs)):
            t = evs[hi]["t"]
            while evs[lo]["t"] < t - window:
                lo += 1
            win = evs[lo:hi+1]; n = len(win)
            out[evs[hi]["event_id"]] = {
                "win_count": n,
                "win_qps": round(n / window, 3),
                "win_unique_qnames": len({w["qname"] for w in win}),
                "win_any_ratio": round(sum(w["qtype"]=="ANY" for w in win)/n, 3),
                "win_nxdomain_ratio": round(sum(w["rcode"]=="NXDOMAIN" for w in win)/n, 3),
                "win_txt_ratio": round(sum(w["qtype"]=="TXT" for w in win)/n, 3),
            }
    return out

def main(argv=None):
    ap = argparse.ArgumentParser(description="Features de janela deslizante (Zeek) anexadas por-evento")
    ap.add_argument("events", nargs="+", help="eventos canonicos (.jsonl)")
    ap.add_argument("--features", required=True, help="features por-evento (.jsonl)")
    ap.add_argument("--window", type=float, default=30.0, help="janela em segundos (default 30)")
    args = ap.parse_args(argv)

    zeek = []
    for path in args.events:
        for line in open(path):
            line = line.strip()
            if not line: continue
            e = json.loads(line)
            if e.get("sensor") != "zeek": continue
            zeek.append({"event_id": e["event_id"], "t": to_epoch(e["timestamp"]),
                         "src": e.get("source_ip"), "qname": e.get("query"),
                         "qtype": canon(e.get("query_type")), "rcode": e.get("response_code")})
    winmap = compute_windows(zeek, args.window)
    NULL = {k: None for k in WIN_KEYS}

    n_aug = 0
    for line in open(args.features):
        line = line.strip()
        if not line: continue
        f = json.loads(line)
        w = winmap.get(f["event_id"])
        f.update(w if w else NULL)
        n_aug += 1 if w else 0
        print(json.dumps(f))
    print(f"[window_features] janela={args.window:g}s | zeek_com_janela={n_aug}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
