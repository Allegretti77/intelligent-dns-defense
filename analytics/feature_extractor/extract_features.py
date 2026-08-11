#!/usr/bin/env python3
"""Feature extractor: eventos DNS canonicos (JSON lines) -> vetores de features
(JSON lines). Uma linha de feature por evento, preservando event_id, sensor e
lab_scenario (o rotulo). Base para o scoring deterministico e para a analise de
separacao baseline vs. ataque.

Features estruturais (sobre o nome inteiro) e de composicao (sobre o rotulo mais
longo -- o "payload" suspeito em tunneling). qtype canonizado (ANY/*/255 -> ANY).
"""
import argparse, json, math, sys
from collections import Counter

QTYPE_CANON = {"*": "ANY", "255": "ANY", "ANY": "ANY"}

def canon_qtype(qt):
    return QTYPE_CANON.get(qt, qt) if qt is not None else None

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in Counter(s).values())

def extract(e: dict) -> dict:
    q = e.get("query") or ""
    labels = [l for l in q.split(".") if l]
    label_lens = [len(l) for l in labels]
    longest = max(labels, key=len) if labels else ""
    ldigits = sum(c.isdigit() for c in longest)
    lspecial = sum((not c.isalnum()) for c in longest)
    answers = e.get("answers")
    if answers is None:
        num_answers = None
        answer_bytes = None
        min_ttl = None
    else:
        num_answers = len(answers)
        answer_bytes = sum(len(a.get("rdata", "")) for a in answers)
        ttls = [a.get("ttl") for a in answers if a.get("ttl") is not None]
        min_ttl = min(ttls) if ttls else None
    qt = canon_qtype(e.get("query_type"))
    return {
        "event_id": e["event_id"],
        "sensor": e["sensor"],
        "lab_scenario": e["lab_scenario"],
        "qname_len": len(q),
        "num_labels": len(labels),
        "max_label_len": max(label_lens) if label_lens else 0,
        "avg_label_len": round(sum(label_lens)/len(label_lens), 2) if label_lens else 0.0,
        "entropy": round(shannon_entropy(longest), 3),
        "numeric_ratio": round(ldigits/len(longest), 3) if longest else 0.0,
        "special_ratio": round(lspecial/len(longest), 3) if longest else 0.0,
        "qtype": qt,
        "qtype_is_any": qt == "ANY",
        "qtype_is_txt": qt == "TXT",
        "response_code": e.get("response_code"),
        "num_answers": num_answers,
        "answer_bytes": answer_bytes,
        "min_ttl": min_ttl,
        "duration_ms": e.get("duration_ms"),
    }

def main(argv=None):
    ap = argparse.ArgumentParser(description="Eventos DNS canonicos -> features (JSON lines)")
    ap.add_argument("infile", nargs="?", default="-", help="arquivo de eventos (.jsonl) ou - (stdin)")
    args = ap.parse_args(argv)
    src = sys.stdin if args.infile == "-" else open(args.infile)
    n = 0
    with src as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            print(json.dumps(extract(json.loads(line))))
            n += 1
    print(f"[feature_extractor] features={n}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
