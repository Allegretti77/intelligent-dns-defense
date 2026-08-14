#!/usr/bin/env python3
"""Constroi PACOTES DE EVIDENCIA por (origem, janela de tempo) a partir de eventos
anonimizados + saida do classificador. Cada pacote e um resumo agregado de um
"incidente" -- o que o agente recebe em vez de eventos crus. O rotulo verdadeiro
(_ground_truth_scenario) fica no pacote so para NOSSA avaliacao; NAO vai ao agente."""
import argparse, json, sys, statistics
from collections import defaultdict, Counter
from datetime import datetime, timezone

def epoch(ts): return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
def iso(e): return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def amean(vals):
    v = [x for x in vals if x is not None]
    return round(statistics.mean(v), 3) if v else None
def amax(vals):
    v = [x for x in vals if x is not None]
    return max(v) if v else None

def build_packages(anon, clf_by_id, window):
    buckets = defaultdict(list)
    for e in anon:
        merged = {**e, **clf_by_id.get(e["event_id"], {})}
        bkey = (e.get("source_ip"), int(epoch(e["timestamp"]) // window))
        buckets[bkey].append(merged)
    pkgs = []
    for (host, bidx), evs in sorted(buckets.items()):
        ts = [epoch(x["timestamp"]) for x in evs]
        preds = Counter(x.get("predicted_class") for x in evs if x.get("predicted_class"))
        dom_pred, dom_n = preds.most_common(1)[0] if preds else ("unknown", 0)
        gt = Counter(x.get("lab_scenario") for x in evs).most_common(1)[0][0]
        pkgs.append({
            "incident_id": f"{host}-{iso(bidx*window)}",
            "src_host": host,
            "window_start": iso(min(ts)), "window_end": iso(max(ts)),
            "duration_s": round(max(ts) - min(ts), 1),
            "event_count": len(evs),
            "sensors": sorted({x.get("sensor") for x in evs if x.get("sensor")}),
            "domains": sorted({x.get("domain") for x in evs if x.get("domain")}),
            "unique_query_shapes": len({x.get("query_shape") for x in evs if x.get("query_shape")}),
            "query_shapes_sample": sorted({x.get("query_shape") for x in evs if x.get("query_shape")})[:3],
            "qtype_distribution": dict(Counter(x.get("query_type") for x in evs)),
            "response_codes": dict(Counter(x.get("response_code") for x in evs if x.get("response_code"))),
            "features_summary": {
                "entropy_mean": amean([x.get("entropy") for x in evs]),
                "entropy_max": amax([x.get("entropy") for x in evs]),
                "max_label_len_max": amax([x.get("max_label_len") for x in evs]),
                "num_answers_mean": amean([x.get("num_answers") for x in evs]),
                "answer_bytes_mean": amean([x.get("answer_bytes") for x in evs]),
                "win_qps_max": amax([x.get("win_qps") for x in evs]),
                "win_unique_qnames_max": amax([x.get("win_unique_qnames") for x in evs]),
                "win_any_ratio_max": amax([x.get("win_any_ratio") for x in evs]),
                "win_txt_ratio_max": amax([x.get("win_txt_ratio") for x in evs]),
            },
            "deterministic": {
                "verdict": dom_pred,
                "verdict_confidence": round(dom_n / len(evs), 3),
                "tunneling_score_mean": amean([x.get("tunneling_score") for x in evs]),
                "amplification_score_mean": amean([x.get("amplification_score") for x in evs]),
            },
            "_ground_truth_scenario": gt,
        })
    return pkgs

def main(argv=None):
    ap = argparse.ArgumentParser(description="Constroi pacotes de evidencia por origem+janela")
    ap.add_argument("anon_events", nargs="+")
    ap.add_argument("--classified", required=True)
    ap.add_argument("--window", type=float, default=60.0)
    args = ap.parse_args(argv)
    anon = [json.loads(l) for p in args.anon_events for l in open(p) if l.strip()]
    clf_by_id = {}
    for l in open(args.classified):
        if l.strip():
            r = json.loads(l); clf_by_id[r["event_id"]] = r
    for p in build_packages(anon, clf_by_id, args.window):
        print(json.dumps(p))
    print(f"[build_evidence] {len(anon)} eventos -> pacotes (janela {args.window:g}s)", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

