#!/usr/bin/env python3
"""Re-identifica eventos com event_id derivado do conteudo (unico, idempotente)."""
import hashlib, json, sys

def make_event_id(e):
    key = "|".join(str(e.get(k)) for k in
                   ("sensor", "timestamp", "source_ip", "dns_id", "query", "query_type"))
    return f"{e.get('sensor')}-{hashlib.sha256(key.encode()).hexdigest()[:12]}"

for path in sys.argv[1:]:
    rows = [json.loads(l) for l in open(path) if l.strip()]
    for e in rows:
        e["event_id"] = make_event_id(e)
    with open(path, "w") as fh:
        for e in rows:
            fh.write(json.dumps(e) + "\n")
    print(f"{path}: {len(rows)} eventos", file=sys.stderr)
