"""Shared helpers for the lab traffic generators.

Everything here is synthetic. Hosts use RFC 5737 documentation addresses
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and the reserved .example
domain space, so nothing in the captures points at a real system.
"""
import math
import os
import struct
import zlib
from scapy.all import Ether, IP, TCP, Raw, wrpcap

LAN_PREFIX = "10.20.0."
GATEWAY = "10.20.0.1"
RESOLVER = "10.20.0.2"


def mac_for(ip):
    """LAN hosts get their own MAC; anything off-LAN is reached via the gateway."""
    if ip.startswith(LAN_PREFIX):
        return "02:00:0a:14:00:%02x" % int(ip.split(".")[-1])
    return "02:00:0a:14:00:01"


def eth(src, dst):
    return Ether(src=mac_for(src), dst=mac_for(dst))


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def lognormal_int(rng, median, sigma, lo, hi):
    return clamp(int(rng.lognormvariate(math.log(median), sigma)), lo, hi)


# ---------------------------------------------------------------- TLS bytes
def _ext(ext_type, body):
    return struct.pack("!HH", ext_type, len(body)) + body


def client_hello(rng, sni):
    """A structurally valid TLS 1.3-style ClientHello so Wireshark dissects it."""
    name = sni.encode()
    sni_ext = _ext(0, struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name)
    groups = _ext(10, struct.pack("!H", 6) + struct.pack("!3H", 0x001D, 0x0017, 0x0018))
    ecpf = _ext(11, b"\x01\x00")
    sigalgs = _ext(13, struct.pack("!H", 8) + struct.pack("!4H", 0x0403, 0x0804, 0x0401, 0x0503))
    alpn = _ext(16, struct.pack("!H", 12) + b"\x02h2" + b"\x08http/1.1")
    versions = _ext(43, b"\x04" + struct.pack("!2H", 0x0304, 0x0303))
    keyshare = _ext(51, struct.pack("!H", 36) + struct.pack("!HH", 0x001D, 32) + rng.randbytes(32))
    exts = sni_ext + groups + ecpf + sigalgs + alpn + versions + keyshare
    suites = struct.pack("!5H", 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F)
    body = (b"\x03\x03" + rng.randbytes(32) + b"\x20" + rng.randbytes(32)
            + struct.pack("!H", len(suites)) + suites + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def server_hello(rng):
    keyshare = _ext(51, struct.pack("!HH", 0x001D, 32) + rng.randbytes(32))
    versions = _ext(43, struct.pack("!H", 0x0304))
    exts = versions + keyshare
    body = (b"\x03\x03" + rng.randbytes(32) + b"\x20" + rng.randbytes(32)
            + struct.pack("!H", 0x1301) + b"\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def change_cipher_spec():
    return b"\x14\x03\x03\x00\x01\x01"


def app_data(rng, total):
    """TLS 'Application Data' records totalling exactly `total` bytes on the wire
    (5-byte header per record, random ciphertext body)."""
    out = b""
    while total > 0:
        size = min(total, 16384 + 5)
        size = max(size, 22)  # header + 17 bytes minimum
        out += b"\x17\x03\x03" + struct.pack("!H", size - 5) + rng.randbytes(size - 5)
        total -= size
    return out


# ------------------------------------------------------------- TCP session
def tcp_conversation(t, cip, sip, cport, sport, msgs, rng, rtt=0.04, mss=1460,
                     ttl_c=64, ttl_s=57):
    """Build a full TCP conversation (handshake, data, FIN teardown).

    msgs is a list of (who, payload_bytes, think_time) with who in {'c','s'}.
    Returns (packets, end_time). Packet timestamps are as seen by a tap on the LAN.
    """
    pkts = []
    cseq = rng.randrange(1, 2**32 - 1)
    sseq = rng.randrange(1, 2**32 - 1)
    ipid = [rng.randrange(1, 60000)]

    def add(who, ts, flags, payload=b"", opts=None):
        if who == "c":
            src, dst, sp, dp, seq, ack, ttl = cip, sip, cport, sport, cseq, sseq, ttl_c
        else:
            src, dst, sp, dp, seq, ack, ttl = sip, cip, sport, cport, sseq, cseq, ttl_s
        ipid[0] = (ipid[0] + 1) % 65535
        tcp = TCP(sport=sp, dport=dp, seq=seq, ack=ack if "A" in flags else 0,
                  flags=flags, window=64240, options=opts or [])
        p = eth(src, dst) / IP(src=src, dst=dst, id=ipid[0], ttl=ttl, flags="DF") / tcp
        if payload:
            p = p / Raw(payload)
        p.time = ts
        pkts.append(p)

    syn_opts = [("MSS", 1460), ("SAckOK", b""), ("WScale", 7)]
    add("c", t, "S", opts=syn_opts)
    cseq += 1
    add("s", t + rtt, "SA", opts=syn_opts)
    sseq += 1
    cur = t + rtt + 0.0002
    add("c", cur, "A")
    last = None
    for who, payload, think in msgs:
        if last is not None and who != last:
            cur += rtt
        last = who
        cur += think
        for i in range(0, len(payload), mss):
            chunk = payload[i:i + mss]
            add(who, cur, "PA", chunk)
            if who == "c":
                cseq += len(chunk)
            else:
                sseq += len(chunk)
            cur += 0.0002
        ack_t = cur + (rtt if who == "c" else 0.0003)
        add("s" if who == "c" else "c", ack_t, "A")
    cur += 0.01
    add("c", cur, "FA")
    cseq += 1
    add("s", cur + rtt, "FA")
    sseq += 1
    add("c", cur + rtt + 0.0003, "A")
    return pkts, cur + rtt + 0.0003


# ------------------------------------------------------------------- output
def write_pcap(path, pkts):
    pkts.sort(key=lambda p: float(p.time))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    wrpcap(path, pkts)
    return len(pkts)


# ------------------------------------------------------ benign HTTPS traffic
BENIGN_SITES = [
    ("198.51.100.%d" % (10 + i), name) for i, name in enumerate([
        "www.news-daily.example", "cdn.photoshare.example", "mail.example.org",
        "shop.example.com", "video.streamhub.example", "docs.office-suite.example",
        "api.weather.example", "static.forum.example", "login.university.example",
        "maps.travel.example", "search.example.net", "updates.os-vendor.example",
        "chat.messenger.example", "music.tunes.example"])
]


def https_session(t, cip, sip, sni, rng, req_sizes, resp_sizes, rtt=None):
    """One TLS session: handshake, then one request/response per size pair.
    A given server always sends the same-sized certificate flight (derived from its name)."""
    flight = 2400 + zlib.crc32(sni.encode()) % 1200
    rtt = rtt if rtt is not None else rng.uniform(0.02, 0.09)
    msgs = [
        ("c", client_hello(rng, sni), 0.001),
        ("s", server_hello(rng) + change_cipher_spec() + app_data(rng, flight), 0.002),
        ("c", change_cipher_spec() + app_data(rng, 74), 0.003),
    ]
    for rq, rs in zip(req_sizes, resp_sizes):
        msgs.append(("c", app_data(rng, rq), rng.uniform(0.01, 0.4)))
        msgs.append(("s", app_data(rng, rs), rng.uniform(0.01, 0.12)))
    return tcp_conversation(t, cip, sip, rng.randint(49152, 65000), 443, msgs, rng, rtt=rtt)


def benign_browsing(rng, client, start, end, mean_gap, pkts, sites=None):
    """Poisson-arriving browsing sessions with log-normal request/response sizes."""
    sites = sites or BENIGN_SITES
    t = start + rng.uniform(0, mean_gap)
    while t < end:
        ip, sni = rng.choice(sites)
        n = rng.choice([1, 1, 2, 3])
        reqs = [lognormal_int(rng, 600, 0.6, 120, 6000) for _ in range(n)]
        resps = [lognormal_int(rng, 3000, 1.1, 200, 40000) for _ in range(n)]
        p, _ = https_session(t, client, ip, sni, rng, reqs, resps)
        pkts.extend(p)
        t += rng.expovariate(1.0 / mean_gap)
