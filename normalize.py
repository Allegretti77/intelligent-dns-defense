#!/usr/bin/env python3
"""Normalizador: roda os tres parsers, funde os streams num dataset unico,
ordena por tempo (UTC ISO8601 ordena lexicograficamente = cronologicamente) e
grava JSON lines. Cada parser e' invocado pela sua CLI (o contrato estavel de
cada coletor), com o mesmo interpretador que roda este script."""
import argparse, json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PARSERS = {
    "bind":     ROOT / "collectors" / "bind_collector" / "parse_bind.py",
    "zeek":     ROOT / "collectors" / "zeek_collector" / "parse_zeek.py",
    "suricata": ROOT / "collectors" / "suricata_collector" / "parse_suricata.py",
}

def run_parser(sensor, logpath, scenario):
    proc = subprocess.run(
        [sys.executable, str(PARSERS[sensor]), str(logpath), "--scenario", scenario],
        capture_output=True, text=True,
    )
    sys.stderr.write(proc.stderr)  # repassa o stats= de cada parser
    if proc.returncode != 0:
        sys.stderr.write(f"[normalize] parser {sensor} FALHOU (rc={proc.returncode})\n")
        return []
    return [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]

def main(argv=None):
    ap = argparse.ArgumentParser(description="Funde BIND+Zeek+Suricata num dataset canonico unico")
    ap.add_argument("--bind")
    ap.add_argument("--zeek")
    ap.add_argument("--suricata")
    ap.add_argument("--scenario", default="unknown",
                    choices=["baseline","dns_tunneling","dns_amplification","fast_flux","unknown"])
    ap.add_argument("--out", required=True, help="arquivo de saida (.jsonl)")
    args = ap.parse_args(argv)

    events = []
    for sensor in ("bind", "zeek", "suricata"):
        path = getattr(args, sensor)
        if path:
            events.extend(run_parser(sensor, path, args.scenario))

    events.sort(key=lambda e: e["timestamp"])   # UTC ISO8601 -> ordem lexicografica = cronologica

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")

    counts = {}
    for e in events:
        counts[e["sensor"]] = counts.get(e["sensor"], 0) + 1
    summary = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    sys.stderr.write(f"[normalize] total={len(events)} ({summary}) -> {out}\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
