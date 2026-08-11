#!/usr/bin/env python3
"""Motor de scoring deterministico (detector sem IA).

Calibra limiares a partir do subconjunto BASELINE (percentil p, default 99), de
modo que os limiares fiquem acima do envelope do trafego legitimo. Depois pontua
cada evento por regras e soma num risk_score (0-100). Como o corpus tem
lab_scenario (gabarito), o modo --evaluate mede precision/recall/falso-positivo.

Entrada: features (JSON lines) do extract_features.py, incluindo lab_scenario.
"""
import argparse, json, sys, statistics

# feature -> pontos se exceder o limiar calibrado (regras numericas, direcao ">")
NUMERIC_RULES = {
    "entropy":       25,   # tunneling
    "max_label_len": 25,   # tunneling
    "numeric_ratio": 15,   # tunneling
    "num_answers":   25,   # amplification
    "answer_bytes":  20,   # amplification
}
ANY_POINTS = 30           # qtype ANY: baseline ~0%, sinal forte de amplification
CUTOFF = 40               # risk_score >= CUTOFF -> "suspeito"

def percentile(data, p):
    data = sorted(v for v in data if v is not None)
    if not data:
        return None
    if len(data) == 1:
        return data[0]
    k = (len(data) - 1) * (p / 100)
    lo = int(k); hi = min(lo + 1, len(data) - 1)
    return data[lo] + (data[hi] - data[lo]) * (k - lo)

def calibrate(baseline_rows, p):
    thr = {}
    for feat in NUMERIC_RULES:
        thr[feat] = percentile([r.get(feat) for r in baseline_rows], p)
    return thr

def score(row, thr):
    s = 0; ind = []
    for feat, pts in NUMERIC_RULES.items():
        v = row.get(feat); t = thr.get(feat)
        if v is not None and t is not None and v > t:
            s += pts; ind.append(feat)
    if row.get("qtype_is_any"):
        s += ANY_POINTS; ind.append("qtype_is_any")
    return min(s, 100), ind

def main(argv=None):
    ap = argparse.ArgumentParser(description="Scoring deterministico calibrado no baseline")
    ap.add_argument("infile", nargs="?", default="-")
    ap.add_argument("--percentile", type=float, default=99.0)
    ap.add_argument("--cutoff", type=float, default=CUTOFF)
    ap.add_argument("--evaluate", action="store_true", help="mede precision/recall vs lab_scenario")
    args = ap.parse_args(argv)
    src = sys.stdin if args.infile == "-" else open(args.infile)
    rows = [json.loads(l) for l in src if l.strip()]

    baseline = [r for r in rows if r.get("lab_scenario") == "baseline"]
    thr = calibrate(baseline, args.percentile)

    for r in rows:
        r["risk_score"], r["indicators"] = score(r, thr)
        r["suspicious"] = r["risk_score"] >= args.cutoff

    if not args.evaluate:
        for r in rows:
            print(json.dumps(r))
        return 0

    print(f"limiares calibrados (baseline p{args.percentile:g}):", file=sys.stderr)
    for f, t in thr.items():
        print(f"  {f:16} > {t}", file=sys.stderr)
    print(f"cutoff risk_score >= {args.cutoff:g}\n", file=sys.stderr)

    scen = {}
    for r in rows:
        d = scen.setdefault(r["lab_scenario"], {"n":0,"flag":0,"score":[]})
        d["n"] += 1; d["flag"] += int(r["suspicious"]); d["score"].append(r["risk_score"])
    print(f"{'cenario':18} {'n':>5} {'flagged':>8} {'taxa':>7} {'score_medio':>12}")
    for s, d in sorted(scen.items()):
        print(f"{s:18} {d['n']:>5} {d['flag']:>8} {d['flag']/d['n']:>6.0%} {statistics.mean(d['score']):>12.1f}")

    tp = sum(1 for r in rows if r["lab_scenario"]!="baseline" and r["suspicious"])
    fn = sum(1 for r in rows if r["lab_scenario"]!="baseline" and not r["suspicious"])
    fp = sum(1 for r in rows if r["lab_scenario"]=="baseline" and r["suspicious"])
    tn = sum(1 for r in rows if r["lab_scenario"]=="baseline" and not r["suspicious"])
    prec = tp/(tp+fp) if tp+fp else 0
    rec  = tp/(tp+fn) if tp+fn else 0
    fpr  = fp/(fp+tn) if fp+tn else 0
    f1   = 2*prec*rec/(prec+rec) if prec+rec else 0
    print(f"\nataque=positivo | TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"precision={prec:.3f}  recall={rec:.3f}  F1={f1:.3f}  taxa_falso_positivo={fpr:.3f}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
