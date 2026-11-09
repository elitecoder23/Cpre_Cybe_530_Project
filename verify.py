#!/usr/bin/env python3
"""Independent check: recompute every answer from the PCAPs with tshark and
compare to the generator's ground truth. Also runs the web page's JS answer
checker (via node) against the key. Exits non-zero on any mismatch.

    python verify.py
"""
import base64
import collections
import json
import os
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
P = lambda n: os.path.join(HERE, "web", "pcaps", n)
_gt = json.load(open(os.path.join(HERE, "instructor", "ground_truth.json")))
truth, SEED = _gt["labs"], _gt["seed"]
fails = []


def tsh(pcap, flt, *fields):
    cmd = ["tshark", "-r", P(pcap), "-Y", flt, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return [l.split("\t") for l in out.splitlines() if l]


def check(name, got, want):
    ok = got == want
    print("%-46s %s" % (name, "ok" if ok else "FAIL got=%r want=%r" % (got, want)))
    if not ok:
        fails.append(name)


# ---------------- Lab 0 (tutorial)
t = truth["0"]; f = "lab0_tutorial.pcap"
allp = tsh(f, "ip", "ip.src", "ip.dst")
pc = collections.Counter(frozenset(r) for r in allp)
(top, topn), (_, nextn) = pc.most_common(2)
check("L0 top pair by packets = infected <-> C2", top, frozenset((t["infected_ip"], t["c2_ip"])))
check("L0 top pair packet count", topn, t["pair_packets"])
check("L0 next pair packet count", nextn, t["next_pair_packets"])
syn = collections.Counter(map(tuple, tsh(f, "tcp.flags.syn==1 && tcp.flags.ack==0", "ip.src", "ip.dst")))
(k0, n0), (_, n1) = syn.most_common(2)
check("L0 connections infected -> C2", (k0, n0), ((t["infected_ip"], t["c2_ip"]), t["n_beacons"]))
check("L0 next pair connections (text says 'at most N')", n1, t["next_pair_connections"])
ts = [float(r[0]) for r in tsh(f, "ip.dst==%s && tcp.flags.syn==1 && tcp.flags.ack==0" % t["c2_ip"], "frame.time_epoch")]
check("L0 every gap is exactly the interval", {round(b - a, 2) for a, b in zip(ts, ts[1:])}, {float(t["interval"])})
conv = subprocess.run(["tshark", "-r", P(f), "-q", "-z", "conv,tcp,ip.addr==%s" % t["c2_ip"]], capture_output=True, text=True).stdout
import re
totals = {(int(m.group(5)), int(m.group(6))) for m in
          (re.search(r"(\d+) (\d+) bytes\s+(\d+) (\d+) bytes\s+(\d+) (\d+) bytes", l) for l in conv.splitlines() if "<->" in l) if m}
check("L0 every C2 conversation has the same (frames, bytes) as the text", totals, {(t["conn_frames"], t["conn_bytes"])})
sni = {r[0] for r in tsh(f, "tls.handshake.type==1 && ip.dst==%s" % t["c2_ip"], "tls.handshake.extensions_server_name")}
check("L0 SNI", sni, {t["c2_sni"]})

# ---------------- Lab 1
t = truth["1"]; f = "lab1_https_beacon.pcap"
syn = tsh(f, "tcp.flags.syn==1 && tcp.flags.ack==0", "ip.src", "ip.dst")
pairs = collections.Counter(map(tuple, syn)).most_common(3)
check("L1 top pair = infected -> C2", pairs[0][0], (t["infected_ip"], t["c2_ip"]))
check("L1 connections to C2", pairs[0][1], t["n_beacons"])
print("   (runner-up pair has %d connections)" % pairs[1][1])
check("L1 clear separation (>3x runner-up)", pairs[0][1] > 3 * pairs[1][1], True)
ts = [float(r[0]) for r in tsh(f, "ip.dst==%s && tcp.flags.syn==1 && tcp.flags.ack==0" % t["c2_ip"], "frame.time_epoch")]
gaps = [b - a for a, b in zip(ts, ts[1:])]
check("L1 median interval", round(statistics.median(gaps)), t["interval_median"])
check("L1 interval range", (round(min(gaps)), round(max(gaps))), (t["interval_min"], t["interval_max"]))
srv = collections.defaultdict(int); port = {}
for s, l, dp in tsh(f, "ip.src==%s" % t["c2_ip"], "tcp.stream", "tcp.len", "tcp.dstport"):
    srv[s] += int(l or 0); port[s] = dp
top = sorted(srv.items(), key=lambda kv: -kv[1])
print("   server bytes per C2 connection: top3 %s, median %d" % ([b for _, b in top[:3]], statistics.median(srv.values())))
check("L1 largest server-bytes connection -> client port", port[top[0][0]], str(t["task_client_port"]))
check("L1 task connection clearly separated (>1.5x next)", top[0][1] > 1.5 * top[1][1], True)
sni = {r[0] for r in tsh(f, "tls.handshake.type==1 && ip.dst==%s" % t["c2_ip"], "tls.handshake.extensions_server_name")}
check("L1 SNI", sni, {t["c2_sni"]})
def conn_bytes(host, server):
    rows = tsh(f, "ip.addr==%s && ip.addr==%s && tcp.len>0" % (host, server), "tcp.stream", "tcp.len")
    d = collections.defaultdict(int)
    for s, l in rows: d[s] += int(l)
    return list(d.values())
def near_median(xs, tol=0.03):
    m = statistics.median(xs); return sum(abs(x - m) <= tol * m for x in xs) / len(xs)
nb, nd = near_median(conn_bytes(t["infected_ip"], t["c2_ip"])), near_median(conn_bytes(t["decoy_ip"], t["decoy_server"]))
print("   share of connections within 3%% of median size: beacon %.2f, decoy %.2f" % (nb, nd))
check("L1 beacon sizes near-identical (>=85%) vs decoy (<50%)", nb >= 0.85 and nd < 0.5, True)

# ---------------- Lab 2
t = truth["2"]; f = "lab2_dns_tunnel.pcap"
txt = collections.Counter(r[0] for r in tsh(f, "dns.qry.type==16 && dns.flags.response==0", "ip.src"))
check("L2 top TXT source = infected", txt.most_common(1)[0][0], t["infected_ip"])
q = tsh(f, 'dns.flags.response==0 && dns.qry.name contains "%s"' % t["domain"], "ip.src", "dns.qry.name", "dns.qry.type", "dns.qry.name.len")
check("L2 tunnel query count", len(q), t["n_tunnel_queries"])
check("L2 all from infected, all TXT", {(r[0], r[2]) for r in q}, {(t["infected_ip"], "16")})
check("L2 dns.qry.name.len field exists", all(r[3].isdigit() for r in q), True)
names = sorted(r[1] for r in q)
data = "".join(n.split(".")[1] for n in names).upper()
dec = base64.b32decode(data + "=" * (-len(data) % 8))
check("L2 decoded file name", dec.split(b"\n")[0].decode(), "FILE:" + t["filename"])
check("L2 decoded size", len(dec), t["secret_bytes"])
others = len(tsh(f, 'dns.flags.response==0 && !(dns.qry.name contains "%s")' % t["domain"], "ip.src"))
print("   other (non-tunnel) queries: %d" % others)
longest_other = max(int(r[0]) for r in tsh(f, 'dns.flags.response==0 && !(dns.qry.name contains "%s")' % t["domain"], "dns.qry.name.len"))
print("   longest non-tunnel name: %d chars vs median tunnel name %d" % (longest_other, statistics.median(int(r[3]) for r in q)))
check("L2 >=90% of tunnel names longer than any other name", sum(int(r[3]) > longest_other for r in q) >= 0.9 * len(q), True)

# ---------------- Lab 3
t = truth["3"]; f = "lab3_icmp_tunnel.pcap"
rq = tsh(f, "icmp.type==8", "ip.src", "ip.dst", "data.len", "icmp.seq", "data.data", "icmp.ident")
by = collections.Counter(r[0] for r in rq)
check("L3 busiest ICMP source = infected", by.most_common(1)[0][0], t["infected_ip"])
inf = [r for r in rq if r[0] == t["infected_ip"] and r[1] == t["server_ip"]]
check("L3 request count", len(inf), t["n_requests"])
check("L3 max data.len", max(int(r[2]) for r in inf), t["max_payload"])
first = min(inf, key=lambda r: int(r[3]))
raw = bytes.fromhex(first[4].replace(":", ""))
check("L3 first command", base64.b64decode(raw[4:]).decode(), t["first_cmd"])
check("L3 payload marker", raw[:4], b"TNL1")
# replies: identical for normal/decoy pings, different for the tunnel
rp = tsh(f, "icmp.type==0", "ip.src", "ip.dst", "icmp.ident", "icmp.seq", "data.data")
reqmap = {(r[0], r[1], r[5], r[3]): r[4] for r in rq}
def same(host):
    xs = [reqmap[(r[1], r[0], r[2], r[3])] == r[4] for r in rp if (r[1], r[0], r[2], r[3]) in reqmap and r[1] == host]
    return set(xs)
check("L3 tunnel replies differ from requests", same(t["infected_ip"]), {False})
check("L3 decoy replies identical to requests", same(t["mtu_host"]), {True})
check("L3 decoy payload size", {r[2] for r in rq if r[0] == t["mtu_host"]}, {"1400"})
check("L3 linux/win payload sizes", ({r[2] for r in rq if r[0] == t["linux_host"]}, {r[2] for r in rq if r[0] == t["win_host"]}), ({"40"}, {"32"}))

# ---------------- web page checker (JS) against the key
sys.path.insert(0, HERE)
import questions as Q
labs = [Q.build_lab0(truth["0"], SEED), Q.build_lab1(truth["1"], SEED), Q.build_lab2(truth["2"], SEED), Q.build_lab3(truth["3"], SEED), Q.build_quiz(SEED)]
cases = []
for lab in labs:
    for qq in lab["questions"]:
        pub = {k: v for k, v in qq.items() if not k.startswith("_")}
        ans = qq["_answer"]
        if qq["type"] == "number" and "-" in str(ans):
            lo, hi = map(int, str(ans).split("-")); good = [lo, hi, (lo + hi) // 2]; bad = [hi + 5, lo - 5]
        else:
            good = [ans, " %s " % ans, str(ans).upper()] if qq["type"] != "number" else [ans, "about %s" % ans]
            bad = ["wrong", "0"] if qq["type"] != "choice" else [o for o in qq["options"] if o != ans][:1]
        cases.append({"q": pub, "good": good, "bad": bad})
json.dump(cases, open("/tmp/claude-0/cases.json", "w"))
js = r'''
const fs=require('fs');global.window={addEventListener(){},scrollTo(){}};global.location={hash:''};
global.localStorage={getItem(){return null},setItem(){}};
const mk=()=>({appendChild(){},setAttribute(){},addEventListener(){},remove(){},set innerHTML(v){},get innerHTML(){return ''}});
global.document={getElementById:mk,createElement:mk,createTextNode:()=>({})};window.LABDATA=[];
eval(fs.readFileSync(process.argv[1],'utf8'));
let bad=0,n=0;for(const c of JSON.parse(fs.readFileSync('/tmp/claude-0/cases.json'))){
 for(const g of c.good){n++;if(!window.__check(c.q,String(g))){bad++;console.log('REJECTED correct',c.q.id,g)}}
 for(const b of c.bad){n++;if(window.__check(c.q,String(b))){bad++;console.log('ACCEPTED wrong',c.q.id,b)}}}
console.log(n+' checks, '+bad+' problems');process.exit(bad?1:0)'''
r = subprocess.run(["node", "-e", js, os.path.join(HERE, "web", "app.js")], capture_output=True, text=True)
print(r.stdout.strip(), r.stderr.strip())
if r.returncode:
    fails.append("web checker")
print("\nFAILED: %s" % fails if fails else "\nAll checks passed.")
sys.exit(1 if fails else 0)
