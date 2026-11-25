#!/usr/bin/env python3
"""Compare R59/R62 paired Datapacket runs and per-thread QEMU samples."""
from __future__ import annotations
import json, math, re, statistics, sys
from pathlib import Path

DL = re.compile(r"^(\S+) mode=(direct|socks5) bytes=(\d+).*?curl_seconds=([0-9.]+) curl_avg_MiBps=([0-9.]+) http_code=(\d+)")
THREAD = re.compile(r"tid=(\d+)/([^:,]+):([0-9.]+)%")
RX = re.compile(r"wan\(default\)_rx=([0-9.]+)MiB/s")

def pct(v, q):
    if not v: return None
    a=sorted(v)
    return a[min(len(a)-1,max(0,math.ceil(q*len(a))-1))]

def load(path):
    p=Path(path)
    d={"downloads":[],"pairs":[],"skipped":[],"errors":[],"samples":[],"config":[]}
    f=p/"download-results.log"
    if f.exists():
        for line in f.read_text(errors="replace").splitlines():
            m=DL.match(line.strip())
            if m:
                label,mode,n,sec,speed,code=m.groups()
                d["downloads"].append({"label":label,"mode":mode,"bytes":int(n),"seconds":float(sec),"speed":float(speed),"http":int(code)})
    for name in ("pairs","skipped","errors"):
        f=p/(name+".log")
        if f.exists(): d[name]=f.read_text(errors="replace").splitlines()
    f=p/"samples.log"
    if f.exists():
        for line in f.read_text(errors="replace").splitlines():
            if not line.startswith("sample="): continue
            me=re.search(r"\belapsed=([0-9.]+)s",line)
            mp=re.search(r"\bproc_cpu=([0-9.]+)%",line)
            threads={name:float(v) for _,name,v in THREAD.findall(line)}
            mrx=RX.search(line)
            d["samples"].append({"elapsed":float(me.group(1)) if me else None,
                                  "proc":float(mp.group(1)) if mp else None,
                                  "threads":threads,"rx":float(mrx.group(1)) if mrx else None})
    f=p/"core.log"
    if f.exists():
        d["config"]=[x.strip() for x in f.read_text(errors="replace").splitlines()
                     if "ChaCha] r51 S2C payload:" in x or "[CHACHA-CONFIG]" in x or "[CHACHA-CONFIG-ACTIVE]" in x or "SSH Cipher:" in x]
    d["path"]=str(p)
    return d

def agg(name,runs):
    downloads=[x for r in runs for x in r["downloads"]]
    direct=[x for x in downloads if x["mode"]=="direct" and x["http"]==200 and x["bytes"]>=95000000]
    socks=[x for x in downloads if x["mode"]=="socks5" and x["http"]==200 and x["bytes"]>=95000000]
    samples=[x for r in runs for x in r["samples"]]
    workers=sorted({t for s in samples for t in s["threads"] if t.startswith("chacha-dec")})
    w={}
    for t in workers:
        v=[s["threads"][t] for s in samples if t in s["threads"]]
        w[t]={"n":len(v),"avg":round(statistics.mean(v),2),"p95":round(pct(v,.95),2),
              "max":round(max(v),2),"active":sum(x>0 for x in v)}
    owner=[s["threads"]["ssh_owner"] for s in samples if "ssh_owner" in s["threads"]]
    rx=[s["rx"] for s in samples if s["rx"] is not None]
    pairs=[x for r in runs for x in r["pairs"] if x.startswith("PAIR PASS:")]
    return {
      "version":name,"pair_count":len(pairs),"direct_count":len(direct),"socks5_count":len(socks),
      "direct_median":round(statistics.median(x["speed"] for x in direct),2) if direct else None,
      "socks5_median":round(statistics.median(x["speed"] for x in socks),2) if socks else None,
      "direct_mean":round(statistics.mean(x["speed"] for x in direct),2) if direct else None,
      "socks5_mean":round(statistics.mean(x["speed"] for x in socks),2) if socks else None,
      "socks_vs_direct_pct":round((statistics.median(x["speed"] for x in socks)/statistics.median(x["speed"] for x in direct)-1)*100,2) if direct and socks and statistics.median(x["speed"] for x in direct)>0 else None,
      "owner_avg":round(statistics.mean(owner),2) if owner else None,
      "owner_p95":round(pct(owner,.95),2) if owner else None,
      "owner_max":round(max(owner),2) if owner else None,
      "workers":w,"sample_count":len(samples),
      "rx_median":round(statistics.median(rx),2) if rx else None,
      "rx_p95":round(pct(rx,.95),2) if rx else None,
      "rx_low_pct":round(sum(x<.05 for x in rx)/len(rx)*100,2) if rx else None,
      "skipped":[x for r in runs for x in r["skipped"]],
      "errors":[x for r in runs for x in r["errors"]],
      "config":[x for r in runs for x in r["config"]],
      "downloads":downloads,"pairs":pairs
    }

def fmt(x): return "n/a" if x is None else str(x)

def main():
    if len(sys.argv)!=6:
        print("usage: analyze_qemu_speedtest_r59_r62.py R59_1 R62_1 R62_2 R59_2 OUTPUT_DIR"); return 2
    r59=agg("R59",[load(sys.argv[1]),load(sys.argv[4])])
    r62=agg("R62",[load(sys.argv[2]),load(sys.argv[3])])
    r59_socks_raw=[x["speed"] for x in r59["downloads"] if x["mode"]=="socks5" and x["http"]==200 and x["bytes"]>=95000000]
    r62_socks_raw=[x["speed"] for x in r62["downloads"] if x["mode"]=="socks5" and x["http"]==200 and x["bytes"]>=95000000]
    delta=round((statistics.median(r62_socks_raw)/statistics.median(r59_socks_raw)-1)*100,2) if r59_socks_raw and r62_socks_raw else None
    data={"environment":"MT7621 QEMU / OpenWrt 24.10.7 / Datapacket Singapore 100 MB / 50 s cap / two paired repeats per version",
          "R59":r59,"R62":r62,"R62_vs_R59_SOCKS5_median_pct":delta}
    out=Path(sys.argv[5]);out.mkdir(parents=True,exist_ok=True)
    (out/"comparison.json").write_text(json.dumps(data,indent=2)+"\n")
    lines=[
      "# R59 vs R62 Datapacket bandwidth comparison — QEMU","",
      "**This is an Internet transfer through an MT7621 emulator in GitHub Actions, not a physical MT7621A router benchmark.**","",
      "| Metric | R59 | R62 |","|---|---:|---:|",
      f"| Valid direct downloads | {r59['direct_count']} | {r62['direct_count']} |",
      f"| Valid SOCKS5 downloads | {r59['socks5_count']} | {r62['socks5_count']} |",
      f"| Matched byte-count pairs | {r59['pair_count']} | {r62['pair_count']} |",
      f"| Direct median | {fmt(r59['direct_median'])} MiB/s | {fmt(r62['direct_median'])} MiB/s |",
      f"| SOCKS5 median | {fmt(r59['socks5_median'])} MiB/s | {fmt(r62['socks5_median'])} MiB/s |",
      f"| SOCKS5 vs direct | {fmt(r59['socks_vs_direct_pct'])}% | {fmt(r62['socks_vs_direct_pct'])}% |",
      f"| R62 SOCKS5 median vs R59 | {fmt(delta)}% |",
      f"| SSH Owner CPU avg / p95 / max | {fmt(r59['owner_avg'])}% / {fmt(r59['owner_p95'])}% / {fmt(r59['owner_max'])}% | {fmt(r62['owner_avg'])}% / {fmt(r62['owner_p95'])}% / {fmt(r62['owner_max'])}% |",
      f"| Per-TID sample count | {r59['sample_count']} | {r62['sample_count']} |",
      f"| WAN RX median / p95 | {fmt(r59['rx_median'])} / {fmt(r59['rx_p95'])} MiB/s | {fmt(r62['rx_median'])} / {fmt(r62['rx_p95'])} MiB/s |",
      f"| RX windows under 0.05 MiB/s | {fmt(r59['rx_low_pct'])}% | {fmt(r62['rx_low_pct'])}% |","",
      "## ChaCha worker CPU","",""
    ]
    for label,data0 in [("R59",r59),("R62",r62)]:
        lines.append("### "+label)
        if not data0["workers"]: lines.append("No ChaCha worker TID samples recorded.")
        for tid,x in data0["workers"].items():
            lines.append(f"- {tid}: avg {x['avg']}%, p95 {x['p95']}%, max {x['max']}%, active {x['active']}/{x['n']} samples")
        lines.append("")
    lines += [
      "## Integrity and limits","",
      "- Each download is accepted only with HTTP 200 and at least 95,000,000 bytes; each direct/SOCKS pair must have equal byte counts.",
      "- The existing benchmark streams to /dev/null and does not calculate SHA-256. The pair check is byte-count equality, not a content-hash proof.",
      "- Each transfer has a 50-second hard cap; skipped transfers are excluded from medians.",
      "- CPU and network samples are measured every 250 ms during SOCKS5 transfers. Low RX windows are diagnostic signals, not definitive stall proof.",
      "- Two repeats are a small sample. Physical MT7621A testing is still required before claiming a real-device speedup.",""
    ]
    (out/"summary.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return 0 if r59["pair_count"]>0 and r62["pair_count"]>0 else 1

if __name__=="__main__":
    raise SystemExit(main())
