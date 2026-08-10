#!/usr/bin/env python3
"""Parser do eve.json do Suricata -> eventos canonicos (schema dns_event v1.0.0).

O Suricata emite a consulta e a resposta como DOIS eventos DNS separados
(dns.type 'query' e 'answer'), ligados por (flow_id, dns.id). Este parser
casa os dois numa transacao unica. Consulta sem resposta -> response null;
resposta sem answer records (NXDOMAIN/NODATA) -> answers [].

Considera apenas event_type == 'dns'. Alertas (event_type 'alert') sao
correlacionados em etapa posterior, nao aqui.
"""
import argparse, json, sys
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0.0"

def to_utc_iso(ts: str) -> str:
    dt = datetime.fromisoformat(ts).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def map_answers(dns: dict):
    """dns.answers[] -> lista canonica. Resposta observada mas sem answers -> []."""
    if "answers" not in dns:
        return []
    out = []
    for a in dns["answers"]:
        ttl = a.get("ttl")
        out.append({
            "rdata": a.get("rdata", ""),
            "rrtype": a.get("rrtype"),
            "ttl": int(ttl) if isinstance(ttl, (int, float)) else None,
        })
    return out

def emit(query_evt, answer_evt, seq):
    """Monta a transacao canonica a partir do par (query, answer). Qualquer um pode ser None."""
    base = query_evt or answer_evt
    dns_q = (query_evt or {}).get("dns", {})
    dns_a = (answer_evt or {}).get("dns", {})
    qname = dns_q.get("rrname") or dns_a.get("rrname")
    qtype = dns_q.get("rrtype") or dns_a.get("rrtype")
    dns_id = dns_q.get("id", dns_a.get("id"))
    if answer_evt is not None:
        response_code = dns_a.get("rcode")
        answers = map_answers(dns_a)
    else:
        response_code = None
        answers = None
    duration_ms = None
    if query_evt is not None and answer_evt is not None:
        tq = datetime.fromisoformat(query_evt["timestamp"])
        ta = datetime.fromisoformat(answer_evt["timestamp"])
        duration_ms = round((ta - tq).total_seconds() * 1000, 3)
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": f"suricata-{seq:08d}",
        "timestamp": to_utc_iso(base["timestamp"]),
        "sensor": "suricata",
        "event_type": "dns_transaction",
        "protocol": base.get("proto"),
        "source_ip": base.get("src_ip"),
        "destination_ip": base.get("dest_ip"),
        "dns_id": dns_id,
        "query": qname,
        "query_type": qtype,
        "response_code": response_code,
        "answers": answers,
        "query_size": None,
        "response_size": None,
        "duration_ms": duration_ms,
        "alert_signature": None,
        "severity": None,
        "lab_scenario": None,
    }

def parse_stream(fh, scenario):
    pending = {}   # (flow_id, dns.id) -> evento de query aguardando resposta
    seq = 0
    for raw in fh:
        raw = raw.strip()
        if not raw:
            continue
        evt = json.loads(raw)
        if evt.get("event_type") != "dns":
            continue
        dns = evt.get("dns", {})
        key = (evt.get("flow_id"), dns.get("id"))
        if dns.get("type") == "query":
            pending[key] = evt
        elif dns.get("type") == "answer":
            q = pending.pop(key, None)
            out = emit(q, evt, seq); out["lab_scenario"] = scenario
            seq += 1
            yield out
    for q in pending.values():
        out = emit(q, None, seq); out["lab_scenario"] = scenario
        seq += 1
        yield out

def main(argv=None):
    ap = argparse.ArgumentParser(description="Suricata eve.json -> eventos DNS canonicos (JSON lines)")
    ap.add_argument("logfile", help="caminho do eve.json (ou - para stdin)")
    ap.add_argument("--scenario", default="unknown",
                    choices=["baseline","dns_tunneling","dns_amplification","fast_flux","unknown"])
    args = ap.parse_args(argv)
    src = sys.stdin if args.logfile == "-" else open(args.logfile)
    n = 0
    with src as fh:
        for evt in parse_stream(fh, args.scenario):
            n += 1; print(json.dumps(evt))
    print(f"[suricata_collector] emitted={n}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
