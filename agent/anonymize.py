#!/usr/bin/env python3
"""Anonimizador: transforma eventos canonicos numa versao segura para envio a uma
API externa. Pseudonimiza IPs (host_N) e dominios (domain_N) de forma estavel,
mascara os nomes de query preservando so a ESTRUTURA (comprimentos de rotulo, sem
conteudo) e descarta o rdata das respostas (mantendo tipo/ttl). Remove qualquer
payload sensivel -- inclusive o segredo (falso) exfiltrado via tunneling."""
import argparse, json, sys

def registered_domain(qname):
    parts = [p for p in qname.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else qname

def build_maps(events):
    ips, doms = set(), set()
    for e in events:
        for k in ("source_ip", "destination_ip"):
            if e.get(k): ips.add(e[k])
        if e.get("query"): doms.add(registered_domain(e["query"]))
    ip_map = {ip: f"host_{i+1}" for i, ip in enumerate(sorted(ips))}
    dom_map = {d: f"domain_{i+1}" for i, d in enumerate(sorted(doms))}
    return ip_map, dom_map

def mask_query(qname, dom_map):
    parts = [p for p in qname.split(".") if p]
    if len(parts) < 2:
        return dom_map.get(qname, "domain_?")
    reg = ".".join(parts[-2:]); sub = parts[:-2]
    shape = ".".join(f"L{len(p)}" for p in sub)
    dl = dom_map.get(reg, "domain_?")
    return f"{shape}.{dl}" if shape else dl

def anonymize(e, ip_map, dom_map):
    out = dict(e)
    for k in ("source_ip", "destination_ip"):
        if out.get(k) is not None:
            out[k] = ip_map.get(out[k], "host_?")
    if out.get("query") is not None:
        out["query_shape"] = mask_query(out["query"], dom_map)
        out["domain"] = dom_map.get(registered_domain(out["query"]), "domain_?")
        del out["query"]
    ans = out.get("answers")
    if ans:
        out["answers"] = [{"rrtype": a.get("rrtype"), "ttl": a.get("ttl")} for a in ans]
    return out

def main(argv=None):
    ap = argparse.ArgumentParser(description="Anonimiza eventos para envio externo seguro")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args(argv)
    events = []
    for path in args.files:
        for l in open(path):
            if l.strip(): events.append(json.loads(l))
    ip_map, dom_map = build_maps(events)
    for e in events:
        print(json.dumps(anonymize(e, ip_map, dom_map)))
    print(f"[anonymize] {len(events)} eventos | {len(ip_map)} hosts | {len(dom_map)} dominios", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
