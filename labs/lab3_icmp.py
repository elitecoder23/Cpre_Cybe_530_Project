"""Lab 3 - covert channel inside ICMP echo (ping) packets.

Normal pings echo the request's data back unchanged and use a standard
payload (32 bytes on Windows, 56 on Linux). The infected host sends echo
requests with a custom, variable-length payload to a remote server and the
server answers with *different* data. A decoy host sends a few large pings
(MTU test) whose replies do echo the request exactly.
"""
import base64
import random
import struct
from scapy.all import IP, ICMP, Raw
from .common import LAN_PREFIX, GATEWAY, eth, benign_browsing, write_pcap

BASE_TIME = 1762300800
DURATION = 600
FIRST_CMD = b"ls /var/backups"
FIRST_REPLY = b"auth.log.1 backup.tar.gz db_dump.sql"


def _ping(t, src, dst, ident, seq, req_data, reply_data, rtt, rng, ttl_reply=64, ttl_req=64):
    q = eth(src, dst) / IP(src=src, dst=dst, ttl=ttl_req, id=rng.randint(1, 65000)) / \
        ICMP(type=8, code=0, id=ident, seq=seq) / Raw(req_data)
    q.time = t
    r = eth(dst, src) / IP(src=dst, dst=src, ttl=ttl_reply, id=rng.randint(1, 65000)) / \
        ICMP(type=0, code=0, id=ident, seq=seq) / Raw(reply_data)
    r.time = t + rtt
    return [q, r]


def _tnl(raw):
    return b"TNL1" + base64.b64encode(raw)


def generate(path, seed):
    rng = random.Random(seed * 100 + 3)
    clients = [LAN_PREFIX + str(n) for n in range(21, 27)]
    infected, mtu_host, linux_host, win_host = rng.sample(clients, 4)
    server = "203.0.113.%d" % rng.randint(10, 200)
    pkts = []

    for c in clients:  # some ordinary web traffic so the capture is not only ICMP
        benign_browsing(rng, c, BASE_TIME, BASE_TIME + DURATION, 90.0, pkts)

    win = b"abcdefghijklmnopqrstuvwabcdefghi"   # standard Windows ping payload
    for k in range(3):
        t0 = BASE_TIME + rng.uniform(10, 500)
        ident = rng.randint(1, 65000)
        for i in range(4):
            pkts += _ping(t0 + i, win_host, GATEWAY, ident, i + 1, win, win, 0.0008, rng, 128, 128)

    ident = rng.randint(1, 65000)   # Linux ping: 16-byte timestamp + 40 bytes (0x10..0x37) = 56
    t0 = BASE_TIME + rng.uniform(30, 300)
    for i in range(20):
        data = struct.pack("<QQ", int(t0 + i), rng.randint(0, 999999)) + bytes(range(0x10, 0x38))
        pkts += _ping(t0 + i, linux_host, "198.51.100.7", ident, i + 1, data, data, 0.031, rng)

    pattern = (b"abcdefghijklmnopqrstuvwxyz" * 60)[:1400]   # decoy: MTU test, identical both ways
    t0 = BASE_TIME + rng.uniform(100, 400)
    ident = rng.randint(1, 65000)
    for i in range(6):
        pkts += _ping(t0 + i, mtu_host, "198.51.100.7", ident, i + 1, pattern, pattern, 0.034, rng)

    # the tunnel: constant ICMP id, custom payloads, replies carry different data
    n_req = rng.randint(60, 80)
    t, sizes = BASE_TIME + 45, []
    for i in range(n_req):
        if i == 0:
            req, rep = _tnl(FIRST_CMD), _tnl(FIRST_REPLY)
        else:
            req = _tnl(rng.randbytes(rng.randint(80, 640)))
            rep = _tnl(rng.randbytes(rng.randint(15, 220)))
        sizes.append(len(req))
        pkts += _ping(t, infected, server, 0x1337, i + 1, req, rep, 0.052 + rng.uniform(-.003, .003),
                      rng, ttl_reply=52)
        t += rng.uniform(1.0, 3.0)

    n = write_pcap(path, pkts)
    return {"infected_ip": infected, "server_ip": server, "mtu_host": mtu_host,
            "linux_host": linux_host, "win_host": win_host, "n_requests": n_req,
            "max_payload": max(sizes), "min_payload": min(sizes), "first_cmd": FIRST_CMD.decode(),
            "icmp_id": 0x1337, "duration_s": DURATION, "packets": n}
