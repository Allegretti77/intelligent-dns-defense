#!/usr/bin/env python3
"""Classificador por TIPO de ataque (deterministico, calibrado no baseline).

Calcula dois scores por evento -- tunneling_score e amplification_score --, cada
um somando as regras caracteristicas daquele ataque. Limiares numericos calibrados
no percentil p do baseline. Veredito = classe de maior score, se passar do corte;
senao 'clean'. Modo --evaluate imprime a matriz de confusao e precision/recall por
classe (usa lab_scenario como gabarito).

Entrada: features enriquecidas com janela (features_windowed.jsonl).
"""
import argparse, json, sys, statistics
from collections import defaultdict

# regras numericas por classe (feature -> pontos se v > limiar_calibrado)
TUNNELING_RULES = {"entropy": 25, "max_label_len": 25, "numeric_ratio": 10,
                   "win_unique_qnames": 25, "win_txt_ratio": 15}
AMPLIFICATION_RULES = {"num_answers": 20, "answer_bytes": 15,
                       "win_qps": 25, "win_any_ratio": 20}
ANY_POINTS = 30   # qtype ANY -> amplification (todas as fontes)
CUTOFF = 40

def percentile(data, p):
    data = sorted(v for v in data if v is not None)
    if not data: return None
    if len(data) == 1: return data[0]
    k = (len(data) - 1) * (p / 100); lo = int(k); hi = min(lo + 1, len(data) - 1)
    return data[lo] + (data[hi] - data[lo]) * (k - lo)

def calibrate(baseline, p):
    feats = set(TUNNELING_RULES) | set(AMPLIFICATION_RULES)
    return {f: percentile([r.get(f) for r in baseline], p) for f in feats}

def score_event(f, thr):
    t = a = 0; ti = []; ai = []
    for feat, pts in TUNNELING_RULES.items():
        v, th = f.get(feat), thr.get(feat)
        if v is not None and th is not None and v > th: t += pts; ti.append(feat)
    for feat, pts in AMPLIFICATION_RULES.items():
        v, th = f.get(feat), thr.get(feat)
        if v is not None and th is not None and v > th: a += pts; ai.append(feat)
    if f.get("qtype_is_any"): a += ANY_POINTS; ai.append("qtype_is_any")
    return min(t, 100), min(a, 100), ti, ai

def verdict(t, a, cutoff):
    if max(t, a) < cutoff: return "clean"
    return "tunneling" if t >= a else "amplification"

def main(argv=None):
    ap = argparse.ArgumentParser(description="Classificador por tipo de ataque")
    ap.add_argument("infile", nargs="?", default="-")
    ap.add_argument("--percentile", type=float, default=99.0)
    ap.add_argument("--cutoff", type=float, default=CUTOFF)
    ap.add_argument("--evaluate", action="store_true")
    args = ap.parse_args(argv)
    src = sys.stdin if args.infile == "-" else open(args.infile)
    rows = [json.loads(l) for l in src if l.strip()]
    baseline = [r for r in rows if r.get("lab_scenario") == "baseline"]
    thr = calibrate(baseline, args.percentile)
    for r in rows:
        t, a, ti, ai = score_event(r, thr)
        r["tunneling_score"], r["amplification_score"] = t, a
        r["predicted_class"] = verdict(t, a, args.cutoff)
    if not args.evaluate:
        for r in rows: print(json.dumps(r))
        return 0

    truth_map = {"baseline": "baseline", "dns_tunneling": "tunneling", "dns_amplification": "amplification"}
    preds = ["clean", "tunneling", "amplification"]
    truths = ["baseline", "tunneling", "amplification"]
    cm = defaultdict(lambda: defaultdict(int))
    for r in rows:
        tr = truth_map.get(r["lab_scenario"], r["lab_scenario"])
        cm[tr][r["predicted_class"]] += 1
    print("MATRIZ DE CONFUSAO (linha=verdade, coluna=previsto)")
    print(f"{'':16}" + "".join(f"{p:>16}" for p in preds))
    for tr in truths:
        print(f"{tr:16}" + "".join(f"{cm[tr][p]:>16}" for p in preds))
    print("\nMETRICAS POR CLASSE")
    for cls in ("tunneling", "amplification"):
        tp = cm[cls][cls]
        fp = sum(cm[t][cls] for t in truths if t != cls)
        fn = sum(cm[cls][p] for p in preds if p != cls)
        prec = tp/(tp+fp) if tp+fp else 0
        rec = tp/(tp+fn) if tp+fn else 0
        f1 = 2*prec*rec/(prec+rec) if prec+rec else 0
        print(f"  {cls:14} precision={prec:.3f} recall={rec:.3f} F1={f1:.3f}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
