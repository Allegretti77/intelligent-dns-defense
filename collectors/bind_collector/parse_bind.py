#!/usr/bin/env python3
"""Parser do query log do BIND9 -> eventos canonicos (schema dns_event v1.0.0).

O query log do BIND registra SO a consulta; o lado da resposta nao esta neste
arquivo, entao response_code/answers/tamanhos saem como null (o caso que o
schema preve). Linhas de outras categorias (ex.: query-errors) nao casam com o
padrao de 'query:' e sao reportadas como puladas, nao fatais.
"""
import argparse, json, re, sys

SCHEMA_VERSION = "1.0.0"

# 2026-08-06T17:14:05.298Z queries: info: client @0x7f.. 192.168.56.101#36474 (lab.local): query: lab.local IN A +E(0)K (192.168.56.1)
LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+queries:\s+\w+:\s+client\s+"
    r"(?:@0x[0-9a-fA-F]+\s+)?"
    r"(?P<src>\d{1,3}(?:\.\d{1,3}){3})#(?P<sport>\d+)\s+"
    r"\((?P<qname_p>[^)]*)\):\s+query:\s+"
    r"(?P<qname>\S+)\s+(?P<qclass>\S+)\s+(?P<qtype>\S+)\s+"
    r"(?P<rest>.*)$"
)
DST_RE = re.compile(r"\((?P<dst>\d{1,3}(?:\.\d{1,3}){3})\)\s*$")


def parse_line(line: str, scenario: str, seq: int):
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    rest = m.group("rest").strip()
    # flags = primeiro token do resto (ex.: +E(0)K); protocolo derivado do flag 'T' (TCP)
    flags_tok = rest.split()[0] if rest and not rest.startswith("(") else ""
    letters = re.sub(r"[^A-Za-z]", "", flags_tok)
    protocol = "TCP" if "T" in letters else ("UDP" if flags_tok else None)
    dst_m = DST_RE.search(rest)
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": f"bind-{seq:08d}",
        "timestamp": m.group("ts"),           # ja vem UTC ISO8601 (print-time iso8601-utc)
        "sensor": "bind",
        "event_type": "dns_transaction",
        "protocol": protocol,
        "source_ip": m.group("src"),
        "destination_ip": dst_m.group("dst") if dst_m else None,
        "dns_id": None,                        # o query log do BIND nao expoe o id da msg
        "query": m.group("qname"),
        "query_type": m.group("qtype"),
        "response_code": None,                 # lado da resposta nao esta no query log
        "answers": None,
        "query_size": None,
        "response_size": None,
        "duration_ms": None,
        "alert_signature": None,
        "severity": None,
        "lab_scenario": scenario,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="BIND query log -> eventos DNS canonicos (JSON lines)")
    ap.add_argument("logfile", help="caminho do queries.log (ou - para stdin)")
    ap.add_argument("--scenario", default="unknown",
                    choices=["baseline", "dns_tunneling", "dns_amplification", "fast_flux", "unknown"])
    args = ap.parse_args(argv)

    src = sys.stdin if args.logfile == "-" else open(args.logfile)
    parsed = skipped = 0
    seq = 0
    with src as fh:
        for line in fh:
            if not line.strip():
                continue
            evt = parse_line(line, args.scenario, seq)
            if evt is None:
                skipped += 1
                continue
            seq += 1
            parsed += 1
            print(json.dumps(evt))
    print(f"[bind_collector] parsed={parsed} skipped={skipped}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
