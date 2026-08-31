#!/usr/bin/env python3
"""Merge Benchmarks/results/*.json into a comparison table."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path


def load_dir(path: Path) -> list[dict]:
    rows = []
    for f in sorted(path.glob("*.json")):
        try:
            data = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            data = [data]
        for row in data:
            row["_file"] = f.name
            rows.append(row)
    return rows


def fmt_num(n: float, digits: int = 2) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.{digits}f}M"
    if n >= 1_000:
        return f"{n / 1_000:.{digits}f}k"
    return f"{n:.{digits}f}"


def fmt_bytes(n: float) -> str:
    n = float(n)
    if abs(n) >= 1 << 30:
        return f"{n / (1 << 30):.2f} GiB"
    if abs(n) >= 1 << 20:
        return f"{n / (1 << 20):.2f} MiB"
    if abs(n) >= 1 << 10:
        return f"{n / (1 << 10):.1f} KiB"
    return f"{n:.0f} B"


def fmt_us(n: float) -> str:
    if n <= 0:
        return "—"
    if n >= 1000:
        return f"{n / 1000:.2f}ms"
    return f"{n:.0f}µs"


def extra_line(r: dict) -> str:
    bits = []
    if r.get("rps"):
        bits.append(f"rps={fmt_num(r['rps'], 1)}")
    if r.get("handshakeP99Us"):
        bits.append(
            f"hs p50/p99={fmt_us(r.get('handshakeP50Us', 0))}/{fmt_us(r['handshakeP99Us'])}"
        )
    if r.get("ingestP99Us"):
        bits.append(
            f"ingest p50/p99={fmt_us(r.get('ingestP50Us', 0))}/{fmt_us(r['ingestP99Us'])}"
        )
    if r.get("firstByteP99Us"):
        bits.append(
            f"1st-byte p50/p99={fmt_us(r.get('firstByteP50Us', 0))}/{fmt_us(r['firstByteP99Us'])}"
        )
    if r.get("lossPct"):
        bits.append(f"loss={r['lossPct']:.1f}%")
    if r.get("loops"):
        bits.append(f"loops={r['loops']}")
    return "  ".join(bits)


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "Benchmarks/results")
    rows = load_dir(root)
    if not rows:
        print(f"no JSON results in {root}", file=sys.stderr)
        sys.exit(1)

    by_scenario: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_scenario[row.get("scenario", "?")].append(row)

    print()
    print("SwiftTCP vs gVisor vs smoltcp")
    print("=" * 108)
    for scenario, items in by_scenario.items():
        print(f"\n## {scenario}")
        print(
            f"{'stack':<18}{'pps':>12}{'L3 Gbps':>10}{'app Gbps':>10}"
            f"{'CPU':>8}{'RSS Δ':>12}{'B/conn':>10}{'rps':>10}{'dur':>6}"
        )
        print("-" * 114)
        items.sort(key=lambda r: r.get("stack", ""))
        for r in items:
            print(
                f"{r.get('stack', '?'):<18}"
                f"{fmt_num(r.get('pps', 0), 1):>12}"
                f"{r.get('gbps', 0):10.3f}"
                f"{r.get('appGbps', 0):10.3f}"
                f"{r.get('cpuCores', 0):8.2f}"
                f"{fmt_bytes(r.get('rssDeltaBytes', 0)):>12}"
                f"{fmt_num(r.get('bytesPerConnection', 0), 0):>10}"
                f"{fmt_num(r.get('rps', 0), 1) if r.get('rps') else '—':>10}"
                f"{r.get('durationS', 0):>6.1f}"
            )
            extra = extra_line(r)
            if extra:
                print(f"  {extra}")
            if r.get("notes"):
                print(f"  {r['notes']}")
    print()
    print("See Benchmarks/SPEC.md for workload definition and fairness notes.")
    out_md = root / "comparison.md"
    lines = ["# Stack comparison\n"]
    for scenario, items in by_scenario.items():
        lines.append(f"\n## {scenario}\n")
        lines.append(
            "| stack | pps | L3 Gbps | app Gbps | CPU | RSS Δ | B/conn | rps | dur | hs p99 | ingest p99 | 1st-byte p99 |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for r in sorted(items, key=lambda x: x.get("stack", "")):
            lines.append(
                f"| {r.get('stack')} | {fmt_num(r.get('pps', 0), 1)} | {r.get('gbps', 0):.3f} "
                f"| {r.get('appGbps', 0):.3f} | {r.get('cpuCores', 0):.2f} "
                f"| {fmt_bytes(r.get('rssDeltaBytes', 0))} "
                f"| {fmt_num(r.get('bytesPerConnection', 0), 0)} "
                f"| {fmt_num(r.get('rps', 0), 1) if r.get('rps') else '—'} "
                f"| {r.get('durationS', 0):.1f}s "
                f"| {fmt_us(r.get('handshakeP99Us', 0))} "
                f"| {fmt_us(r.get('ingestP99Us', 0))} "
                f"| {fmt_us(r.get('firstByteP99Us', 0))} |"
            )
            extra = extra_line(r)
            if extra or r.get("notes"):
                note = r.get("notes", "")
                if extra:
                    lines.append(f"\n_{extra}_")
                if note:
                    lines.append(f"\n{note}")
    out_md.write_text("\n".join(lines) + "\n")
    print(f"wrote {out_md}")


if __name__ == "__main__":
    main()
