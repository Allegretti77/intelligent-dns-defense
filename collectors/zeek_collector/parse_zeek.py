#!/usr/bin/env python3
"""Parser do dns.log do Zeek (TSV) -> eventos canonicos (schema dns_event v1.0.0).

Le o cabecalho #fields dinamicamente (nao assume indice de coluna). Cada linha de
dados = uma transacao. Distingue 'resposta nao observada' (rcode ausente -> null)
de 'resposta sem registros' (NXDOMAIN/NODATA -> answers []).

Limitacao conhecida: o dns.log usa ',' como set_separator (answers/TTLs). Se um
rdata contiver ',', o split fica ambiguo. Os dados do lab nao disparam isso;
para robustez futura, considere emitir o dns.log em JSON.
"""
import argparse,hashlib, json, sys
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0.0"

def make_event_id(sensor, timestamp, source_ip, dns_id, query, query_type):
    key = "|".join(str(x) for x in (sensor, timestamp, source_ip, dns_id, query, query_type))
    return f"{sensor}-{hashlib.sha256(key.encode()).hexdigest()[:12]}"

UNSET = "-"

def _v(val):
    return None if val == UNSET else val

def _split_set(val):
    if val in (UNSET, "(empty)", ""):
        return []
    return val.split(",")

def zeek_ts_to_iso(ts: str) -> str:
    return datetime.fromtimestamp(float(ts), tz=timezone.utc)\
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def build_answers(ans_field, ttl_field):
    rdatas = _split_set(ans_field)
    ttls = _split_set(ttl_field)
    out = []
    for i, rd in enumerate(rdatas):
        ttl = None
        if i < len(ttls):
            try:
                ttl = int(float(ttls[i]))
            except ValueError:
                ttl = None
        out.append({"rdata": rd, "rrtype": None, "ttl": ttl})
    return out

def parse_stream(fh, scenario):
    fields = None
    seq = 0
    for raw in fh:
        line = raw.rstrip("\n")
        if line.startswith("#"):
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            continue
        if fields is None or not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) != len(fields):
            yield ("skip", None); continue
        row = dict(zip(fields, cols))
        rcode_name = _v(row.get("rcode_name", UNSET))
        answers = None if rcode_name is None else build_answers(
            row.get("answers", UNSET), row.get("TTLs", UNSET))
        rtt = _v(row.get("rtt", UNSET))
        duration_ms = round(float(rtt) * 1000, 3) if rtt is not None else None
        trans_id = _v(row.get("trans_id", UNSET))
        proto = _v(row.get("proto", UNSET))
        ts_iso = zeek_ts_to_iso(row["ts"])
        yield ("event", {
            "schema_version": SCHEMA_VERSION,
            "event_id": make_event_id("zeek", ts_iso, row.get("id.orig_h"), _v(row.get("trans_id", UNSET)), _v(row.get("query", UNSET)), _v(row.get("qtype_name", UNSET))),
            "timestamp": ts_iso,
            "sensor": "zeek",
            "event_type": "dns_transaction",
            "protocol": proto.upper() if proto else None,
            "source_ip": row.get("id.orig_h"),
            "destination_ip": _v(row.get("id.resp_h", UNSET)),
            "dns_id": int(trans_id) if trans_id is not None else None,
            "query": _v(row.get("query", UNSET)),
            "query_type": _v(row.get("qtype_name", UNSET)),
            "response_code": rcode_name,
            "answers": answers,
            "query_size": None,
            "response_size": None,
            "duration_ms": duration_ms,
            "alert_signature": None,
            "severity": None,
            "lab_scenario": scenario,
        })
        seq += 1

def main(argv=None):
    ap = argparse.ArgumentParser(description="Zeek dns.log -> eventos DNS canonicos (JSON lines)")
    ap.add_argument("logfile", help="caminho do dns.log (ou - para stdin)")
    ap.add_argument("--scenario", default="unknown",
                    choices=["baseline","dns_tunneling","dns_amplification","fast_flux","unknown"])
    args = ap.parse_args(argv)
    src = sys.stdin if args.logfile == "-" else open(args.logfile)
    parsed = skipped = 0
    with src as fh:
        for kind, evt in parse_stream(fh, args.scenario):
            if kind == "event":
                parsed += 1; print(json.dumps(evt))
            else:
                skipped += 1
    print(f"[zeek_collector] parsed={parsed} skipped={skipped}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
