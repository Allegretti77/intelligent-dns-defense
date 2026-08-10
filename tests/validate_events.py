#!/usr/bin/env python3
"""Le eventos DNS canonicos (JSON lines) do stdin e valida cada um contra
schemas/dns_event.schema.json. Sai !=0 se algum falhar. Reutilizavel por
qualquer parser (bind, zeek, suricata)."""
import json, sys
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
schema = json.loads((ROOT / "schemas" / "dns_event.schema.json").read_text())
v = Draft202012Validator(schema)

ok = bad = 0
for i, line in enumerate(sys.stdin, 1):
    line = line.strip()
    if not line:
        continue
    evt = json.loads(line)
    errs = list(v.iter_errors(evt))
    if errs:
        bad += 1
        print(f"[FALHOU] evento {i}: {errs[0].message}", file=sys.stderr)
    else:
        ok += 1
print(f"[validate_events] validos={ok} invalidos={bad}", file=sys.stderr)
sys.exit(1 if bad else 0)
