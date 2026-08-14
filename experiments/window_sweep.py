#!/usr/bin/env python3
"""Varredura de tamanho de janela: para cada W, regenera features de janela e
classifica, colhendo recall por classe e falsos positivos no baseline."""
import json, subprocess, sys
from collections import defaultdict

EVENTS = ["datasets/baseline_unified.jsonl", "datasets/tunneling_unified.jsonl",
          "datasets/amplification_unified.jsonl"]
FEATURES = "datasets/features_all.jsonl"
PY = sys.executable
WINDOWS = [1, 10, 30, 60]

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

print(f"{'janela':>8}{'tun_recall':>12}{'amp_recall':>12}{'base_FP':>10}")
for W in WINDOWS:
    # 1) regenera features de janela com este W
    wf = run([PY, "analytics/feature_extractor/window_features.py", *EVENTS,
              "--features", FEATURES, "--window", str(W)])
    open("/tmp/sweep_wf.jsonl", "w").write(wf.stdout)
    # 2) classifica (sem --evaluate: queremos as linhas com predicted_class)
    cl = run([PY, "analytics/rule_engine/classify_events.py", "/tmp/sweep_wf.jsonl"])
    rows = [json.loads(l) for l in cl.stdout.splitlines() if l.strip()]
    # 3) mede
    cnt = defaultdict(lambda: defaultdict(int))
    for r in rows:
        cnt[r["lab_scenario"]][r["predicted_class"]] += 1
    tun = cnt["dns_tunneling"]; amp = cnt["dns_amplification"]; base = cnt["baseline"]
    tun_rec = tun["tunneling"] / max(sum(tun.values()), 1)
    amp_rec = amp["amplification"] / max(sum(amp.values()), 1)
    base_fp = (sum(base.values()) - base["clean"]) / max(sum(base.values()), 1)
    print(f"{W:>7}s{tun_rec:>12.3f}{amp_rec:>12.3f}{base_fp:>10.3f}")
