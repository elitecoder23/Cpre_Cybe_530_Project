"""Lab 1 - C2 beaconing hidden inside HTTPS.

Six workstations browse normally for 30 minutes. One of them is infected and
phones home to a command-and-control (C2) server every ~60 s (+/-10% jitter).
A second host polls a mail server on a regular schedule (a decoy: regular
timing, but variable payload sizes). Payloads are encrypted, so the only clues
are timing, size, and destination.
"""
import random
from statistics import median
from .common import (LAN_PREFIX, BENIGN_SITES, benign_browsing, https_session,
                     lognormal_int, write_pcap)

BASE_TIME = 1762300800  # fixed so captures are reproducible
DURATION = 1800
C2_SNI = "api.cloudmetrics.example"
MAIL_IP, MAIL_SNI = "198.51.100.77", "imap.mailhost.example"


def generate(path, seed):
    rng = random.Random(seed * 100 + 1)
    clients = [LAN_PREFIX + str(n) for n in range(21, 27)]
    infected = rng.choice(clients)
    decoy = rng.choice([c for c in clients if c != infected])
    c2_ip = "203.0.113.%d" % rng.randint(10, 200)
    pkts = []

    # normal browsing for everyone (the infected host browses too)
    for c in clients:
        benign_browsing(rng, c, BASE_TIME, BASE_TIME + DURATION, 45.0, pkts)

    # decoy: mail client polls every ~300 s, but sizes vary a lot
    t = BASE_TIME + rng.uniform(10, 60)
    while t < BASE_TIME + DURATION - 5:
        p, _ = https_session(t, decoy, MAIL_IP, MAIL_SNI, rng,
                             [lognormal_int(rng, 900, 0.8, 200, 5000)],
                             [lognormal_int(rng, 6000, 1.0, 300, 50000)])
        pkts.extend(p)
        t += 300 + rng.uniform(-2, 2)

    # the beacon: new connection every 60 s +/-10%, near-constant sizes
    t = BASE_TIME + rng.uniform(15, 50)
    task_idx = rng.randint(12, 22)
    starts, idx, task_cport = [], 0, None
    while t < BASE_TIME + DURATION - 70:
        idx += 1
        req, resp = rng.randint(276, 284), rng.randint(160, 168)
        if idx == task_idx:
            resp = rng.randint(4200, 4400)       # C2 sends a task
        if idx == task_idx + 1:
            req = rng.randint(1900, 2000)        # implant uploads results
        p, _ = https_session(t, infected, c2_ip, C2_SNI, rng, [req], [resp],
                             rtt=0.045 + rng.uniform(-0.002, 0.002))
        if idx == task_idx:
            task_cport = p[0][1].sport  # TCP layer of the SYN
        pkts.extend(p)
        starts.append(t)
        t += 60 * rng.uniform(0.9, 1.1)

    n = write_pcap(path, pkts)
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    return {
        "infected_ip": infected, "decoy_ip": decoy, "decoy_server": MAIL_IP,
        "c2_ip": c2_ip, "c2_sni": C2_SNI, "n_beacons": idx,
        "task_client_port": task_cport,
        "interval_median": round(median(gaps)),
        "interval_min": round(min(gaps)), "interval_max": round(max(gaps)),
        "duration_s": DURATION, "packets": n, "task_beacon_index": task_idx,
    }
