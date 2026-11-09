"""Lab 0 - tutorial (worked example).

A short, easy capture used to teach the method before the real labs: three
workstations browse over HTTPS for 4 minutes and one of them checks in with a
C2 server every exactly 15 s using identical-size messages. There is no jitter
and no decoy, so the pattern is obvious and a student can follow the steps.
"""
import random
from scapy.all import IP, TCP
from .common import LAN_PREFIX, benign_browsing, https_session, write_pcap

BASE_TIME = 1762300800
DURATION = 240
SNI = "updates.softsync.example"
INTERVAL = 15


def generate(path, seed):
    rng = random.Random(seed * 100 + 4)
    clients = [LAN_PREFIX + str(n) for n in (21, 22, 23)]
    infected = rng.choice(clients)
    c2_ip = "203.0.113.%d" % rng.randint(10, 200)
    pkts = []
    for c in clients:
        benign_browsing(rng, c, BASE_TIME, BASE_TIME + DURATION, 20.0, pkts)
    t, n, conn = BASE_TIME + rng.uniform(5, 12), 0, None
    while t < BASE_TIME + DURATION - 20:
        n += 1
        p, _ = https_session(t, infected, c2_ip, SNI, rng, [200], [120], rtt=0.04)
        conn = (len(p), sum(len(x) for x in p))   # frames and bytes per connection
        pkts.extend(p)
        t += INTERVAL
    pair = lambda x: frozenset((x[IP].src, x[IP].dst))
    counts = {}
    for x in pkts:
        counts[pair(x)] = counts.get(pair(x), 0) + 1
    top = counts.pop(frozenset((infected, c2_ip)))
    syn = {}
    for x in pkts:
        if x[TCP].flags == "S":
            syn[pair(x)] = syn.get(pair(x), 0) + 1
    syn.pop(frozenset((infected, c2_ip)))
    count = write_pcap(path, pkts)
    return {"infected_ip": infected, "c2_ip": c2_ip, "c2_sni": SNI, "interval": INTERVAL,
            "n_beacons": n, "duration_s": DURATION, "packets": count,
            "pair_packets": top, "next_pair_packets": max(counts.values()),
            "next_pair_connections": max(syn.values()),
            "conn_frames": conn[0], "conn_bytes": conn[1]}
