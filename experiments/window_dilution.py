#!/usr/bin/env python3
"""Isola a feature de janela: mostra a DILUICAO da rajada de amplificacao (win_qps
cai quando a janela cresce) contra a robustez do tunneling (win_unique_qnames nao
cai). Recall de detectores de UMA feature so, limiar = p99 do baseline."""
import json, subprocess, sys, statistics

EVENTS = ["datasets/baseline_unified.jsonl", "datasets/tunneling_unified.jsonl",
          "datasets/amplification_unified.jsonl"]
FEATURES = "datasets/features_all.jsonl"
PY_EXE = sys.executable
WINDOWS = [1, 5, 10, 30, 60]

def pctl(data, p):
    d = sorted(v for v in data if v is not None)
    if not d: return None
    if len(d)==1: return d[0]
    k=(len(d)-1)*(p/100); lo=int(k); hi=min(lo+1,len(d)-1)
    return d[lo]+(d[hi]-d[lo])*(k-lo)

def col(rows, scen, feat):
    return [r[feat] for r in rows if r["lab_scenario"]==scen and r.get(feat) is not None]

print(f"{'janela':>7}{'amp_qps':>9}{'base_qps':>10}{'amp/base':>9}{'amp_rec(qps)':>14}   |{'tun_uniq':>9}{'tun_rec(uniq)':>15}")
for W in WINDOWS:
    wf = subprocess.run([PY_EXE, "analytics/feature_extractor/window_features.py", *EVENTS,
                         "--features", FEATURES, "--window", str(W)], capture_output=True, text=True)
    rows = [json.loads(l) for l in wf.stdout.splitlines() if l.strip()]
    base_q = col(rows,"baseline","win_qps"); amp_q = col(rows,"dns_amplification","win_qps")
    base_u = col(rows,"baseline","win_unique_qnames"); tun_u = col(rows,"dns_tunneling","win_unique_qnames")
    thr_q = pctl(base_q,99); thr_u = pctl(base_u,99)
    amp_rec = sum(v>thr_q for v in amp_q)/len(amp_q) if amp_q else 0
    tun_rec = sum(v>thr_u for v in tun_u)/len(tun_u) if tun_u else 0
    am=statistics.mean(amp_q); bm=statistics.mean(base_q); tm=statistics.mean(tun_u)
    print(f"{W:>6}s{am:>9.2f}{bm:>10.2f}{am/bm:>9.2f}{amp_rec:>14.3f}   |{tm:>9.1f}{tun_rec:>15.3f}")
