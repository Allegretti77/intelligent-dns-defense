#!/usr/bin/env python3
"""Valida schemas/dns_event.schema.json e um conjunto de eventos-exemplo
derivados dos logs reais do laboratorio (BIND, Zeek, Suricata)."""
import json, sys
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
schema = json.loads((ROOT / "schemas" / "dns_event.schema.json").read_text())

Draft202012Validator.check_schema(schema)
print("[OK] schema e um JSON Schema (Draft 2020-12) valido")
v = Draft202012Validator(schema)

base = {
  "schema_version": "1.0.0", "event_id": "x", "timestamp": "2026-08-06T19:21:01.400Z",
  "sensor": "suricata", "event_type": "dns_transaction", "protocol": "UDP",
  "source_ip": "192.168.56.101", "destination_ip": "192.168.56.1", "dns_id": 14576,
  "query": "lab.local", "query_type": "A", "response_code": "NOERROR",
  "answers": [{"rdata": "192.168.56.1", "rrtype": "A", "ttl": 604800}],
  "query_size": None, "response_size": None, "duration_ms": None,
  "alert_signature": None, "severity": None, "lab_scenario": "baseline",
}
# BIND so observa a consulta -> lado da resposta todo NULL (o caso critico)
bind_only = {**base, "sensor": "bind", "event_id": "b", "protocol": None,
             "destination_ip": None, "dns_id": None, "response_code": None, "answers": None}

validos = {"suricata (A)": base, "bind (query-only, resposta NULL)": bind_only}
invalidos = {
  "falta 'query'":            {k: v for k, v in base.items() if k != "query"},
  "campo inesperado":         {**base, "backdoor": "x"},
  "sensor fora do enum":      {**base, "sensor": "tcpdump"},
  "lab_scenario invalido":    {**base, "lab_scenario": "hax"},
}

falhas = 0
print("\n-- devem passar --")
for nome, evt in validos.items():
    erros = list(v.iter_errors(evt))
    ok = not erros
    falhas += 0 if ok else 1
    print(f"  [{'OK' if ok else 'FALHOU'}] {nome}")

print("\n-- devem ser rejeitados --")
for nome, evt in invalidos.items():
    erros = list(v.iter_errors(evt))
    ok = bool(erros)
    falhas += 0 if ok else 1
    print(f"  [{'OK (rejeitou)' if ok else 'FALHOU (passou!)'}] {nome}")

sys.exit(1 if falhas else 0)
