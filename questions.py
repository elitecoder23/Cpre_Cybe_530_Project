"""Question, hint, and walkthrough definitions for the labs.

Each build_labN(truth) turns the generator's ground truth into the content
the web page shows. Answers are never stored in plain text in the page data:
they are salted SHA-256 hashes (see answer_hash). The same function is
implemented in web/app.js.
"""
import hashlib
import random
import re

SALT = "hunting-labs-v1"


def norm(s):
    s = re.sub(r"\s+", " ", str(s).strip().lower()).strip("\"'`")
    return s.rstrip(".")


def number_of(s):
    m = re.search(r"-?\d+(?:\.\d+)?", str(s).replace(",", ""))
    return str(int(round(float(m.group())))) if m else ""


def answer_hash(qid, value):
    return hashlib.sha256(("%s|%s|%s" % (SALT, qid, value)).encode()).hexdigest()


def text_q(qid, prompt, answers, hints, explain, display=None):
    return {"id": qid, "type": "text", "prompt": prompt, "hints": hints, "explain": explain,
            "hashes": [answer_hash(qid, norm(a)) for a in answers], "_answer": display or answers[0]}


def num_q(qid, prompt, accept, hints, explain, display=None):
    accept = list(accept)
    return {"id": qid, "type": "number", "prompt": prompt, "hints": hints, "explain": explain,
            "hashes": [answer_hash(qid, str(a)) for a in accept],
            "_answer": display or (str(accept[0]) if len(accept) == 1 else "%d-%d" % (accept[0], accept[-1]))}


def choice_q(qid, prompt, correct, wrong, hints, explain, rng):
    opts = [correct] + list(wrong)
    rng.shuffle(opts)
    return {"id": qid, "type": "choice", "prompt": prompt, "options": opts, "hints": hints,
            "explain": explain, "hashes": [answer_hash(qid, norm(correct))], "_answer": correct}


# ------------------------------------------------------------------- Lab 1
def build_lab1(t, seed):
    rng = random.Random(seed + 11)
    c2 = "C2_IP"
    qs = [
        text_q("l1q1", "Which internal IP address belongs to the infected host?", [t["infected_ip"]],
               ["Statistics > Conversations > TCP shows one row per connection. Look for one pair of addresses with far more connections than any other pair.",
                "Apply the filter tcp.flags.syn == 1 && tcp.flags.ack == 0 so only new connections remain, then check which external address a single internal host keeps reconnecting to."],
               "One internal host opened about %d connections to the same external address; no other host/server pair comes close." % t["n_beacons"]),
        text_q("l1q2", "What is the IP address of the command-and-control (C2) server?", [t["c2_ip"]],
               ["It is the external address the infected host keeps reconnecting to.",
                "Filter ip.src == INFECTED_IP && tcp.flags.syn == 1 && tcp.flags.ack == 0 and sort by the Destination column."],
               "Connections to this address repeat on a steady schedule; browsing traffic does not."),
        num_q("l1q3", "How many TCP connections did the infected host open to the C2 server?", [t["n_beacons"]],
              ["Count only connection starts (SYN without ACK), not every packet.",
               "Filter ip.src == INFECTED_IP && ip.dst == %s && tcp.flags.syn == 1 && tcp.flags.ack == 0 and read the Displayed count in the status bar." % c2],
              "The implant opens one short connection per check-in, so the connection count equals the number of beacons."),
        num_q("l1q4", "Roughly how many seconds pass between beacons? (Give a whole number of seconds.)",
              range(t["interval_min"] - 1, t["interval_max"] + 2),
              ["Show only the SYN packets to the C2 server, then add a column for frame.time_delta_displayed (expand Frame in the packet details, right-click Time delta from previous displayed frame > Apply as Column).",
               "Look at the typical value in that column. It is not exactly constant: the malware adds a little random jitter."],
              "About 60 s with roughly +/-10%% jitter (observed %d-%d s). Jitter is meant to defeat detection that looks for an exact interval." % (t["interval_min"], t["interval_max"])),
        num_q("l1q5", "One check-in was different: the C2 server sent back a much larger response (a tasking). What was the infected host's TCP port on that connection?",
              [t["task_client_port"]],
              ["Compare how much data the server sends in each beacon connection. Statistics > Conversations > TCP, tick 'Limit to display filter' with ip.addr == %s, and sort by 'Bytes B -> A' (server to client). Nearly all rows are almost identical." % c2,
               "One conversation sends far more server data than the rest. In that row, Port A is the infected host's TCP port."],
              "Quiet check-ins are tiny and nearly identical in size. The single large reply is the C2 handing out a task."),
        text_q("l1q6", "Even though the session is encrypted, which server name (SNI) does the infected host send in its TLS ClientHello?",
               [t["c2_sni"]],
               ["The server name is sent in clear text during the TLS handshake (before encryption starts).",
                "Filter tls.handshake.type == 1 && ip.dst == %s and expand Transport Layer Security > Handshake Protocol: Client Hello > Extension: server_name." % c2],
               "TLS 1.3 without ECH still exposes the SNI. It names a plausible-looking 'metrics' service."),
        choice_q("l1q7", "Host %s also connects to %s on a regular schedule (about every 5 minutes). Why is it NOT the malware?" % (t["decoy_ip"], t["decoy_server"]),
                 "Its request and response sizes vary a lot, unlike the near-identical sizes of the beacon.",
                 ["Its connections are spaced much farther apart, and a beacon must be faster than once a minute.",
                  "It uses port 443, and malware never hides inside traffic on that port.",
                  "Regular timing is normal for any program, so periodic connections never need investigation."],
                 ["Regular timing alone is not proof. Compare the sizes of the packets in each connection."],
                 "Regularity is a lead, not a verdict. A mail client polls on a timer too, but its payload sizes follow the mailbox contents; the beacon's sizes barely move.", rng),
        choice_q("l1q8", "The payload is encrypted. Which combination of observable features can still expose the beacon?",
                 "Timing, sizes, and destination (including the SNI)",
                 ["The decrypted HTTP headers and cookies sent in each request", "The TLS session keys negotiated during the handshake exchange", "The server's private key, once the capture file is opened"],
                 ["Think about what an observer on the wire can see without decrypting anything."],
                 "Encryption hides content, not metadata. Defenders hunt with timing, size, and destination.", rng),
    ]
    walk = [
        "Step 1 - Find the pair. Statistics > Conversations > TCP: the pair %s <-> %s has %d connections; every other pair has only a handful." % (t["infected_ip"], t["c2_ip"], t["n_beacons"]),
        "Step 2 - Measure timing. Filter ip.dst == %s && tcp.flags.syn == 1 && tcp.flags.ack == 0 and add frame.time_delta_displayed: about 60 s apart (observed %d-%d s), i.e. 60 s with ~10%% jitter." % (t["c2_ip"], t["interval_min"], t["interval_max"]),
        "Step 3 - Measure sizes. Every check-in transfers almost the same number of bytes in each direction (a ~280-byte request and ~165-byte reply after the handshake). Check-in #%d breaks the pattern: the server sends about 4.3 KB more than usual (a task), and the next check-in uploads about 1.9 KB (the result). In Statistics > Conversations, these are the two outlier rows among near-identical ones." % t["task_beacon_index"],
        "Step 4 - Rule out the decoy. %s polls %s about every 300 s, but its sizes vary widely, so it is a mail client, not an implant." % (t["decoy_ip"], t["decoy_server"]),
        "Detection logic: group connections by (source, destination); look for low variance in inter-arrival time and in bytes per connection; then check the destination's reputation and the SNI. Mitigation: egress allow-listing or a TLS-inspecting proxy, plus beacon-analytics alerts on low-variance periodic connections.",
    ]
    return {"id": "lab1", "title": "Lab 1: Beaconing inside HTTPS", "layer": "Transport / Application (TCP, TLS)",
            "pcap": "pcaps/lab1_https_beacon.pcap",
            "intro": ["Six workstations (10.20.0.21 - 10.20.0.26) sit behind a gateway. Your IDS raised a 'possible beaconing' alert, but every flow is TLS on port 443, so you cannot read any content. The capture covers 30 minutes.",
                      "Goal: identify the infected host and describe its behavior using only timing, packet size, and destination."],
            "questions": qs, "walkthrough": walk}


# ------------------------------------------------------------------- Lab 2
def build_lab2(t, seed):
    rng = random.Random(seed + 12)
    dom = "TUNNEL_DOMAIN"
    qs = [
        text_q("l2q1", "Which internal host is tunneling data over DNS?", [t["infected_ip"]],
               ["Filter dns.qry.type == 16 (TXT queries) and look at the Source column. Several hosts send some TXT queries; look for one with many.",
                "Add dns.qry.name.len as a column (right-click the field > Apply as Column) and sort. Normal names are short and readable."],
               "One host sends many long, random-looking TXT queries to a single domain."),
        text_q("l2q2", "Which domain are the tunnel queries sent to?", [t["domain"]],
               ["A DNS name is read right to left. The last two labels are the registered domain.",
                "Statistics > DNS, or sort the long queries by name: they all end in the same two labels."],
               "Every tunnel query ends in the attacker's domain; its authoritative server receives the data."),
        num_q("l2q3", "How many DNS queries (not responses) were sent to that domain?", [t["n_tunnel_queries"]],
              ["Use dns.flags.response == 0 so responses are excluded.",
               "Filter dns.flags.response == 0 && dns.qry.name contains \"%s\" and read the Displayed count in the status bar." % dom],
              "Each query carries one 46-character chunk of the file, so the count tells you roughly how much data left."),
        choice_q("l2q4", "Which DNS record type does the tunnel use?", "TXT", ["A", "AAAA", "MX"],
                 ["Look at dns.qry.type or the 'Type' field in the Queries section of one tunnel packet."],
                 "TXT records can carry arbitrary text, so tunneling tools favor them; the replies carry data back.", rng),
        text_q("l2q5", "Decode the exfiltrated data. What is the name of the file being stolen? (It appears at the very start of the decoded data.)",
               [t["filename"]],
               ["Each name has the form SEQ.DATA.DOMAIN (a 4-hex-digit sequence number, the data, and the domain). The data labels use only a-z and 2-7, which is the Base32 alphabet.",
                "Export the names (tshark -r lab2_dns_tunnel.pcap -Y 'dns.flags.response==0 && dns.qry.name contains \"%s\"' -T fields -e dns.qry.name), sort by sequence, join the data labels, uppercase them, pad with '=' to a multiple of 8, and decode with Python's base64.b32decode." % dom],
               "Base32-decoding the joined labels gives the start of a CSV file: 'FILE:%s' followed by employee records." % t["filename"]),
        choice_q("l2q6", "Which pair of features best separates the tunnel from normal DNS?",
                 "Long, high-entropy subdomains with a very large number of unique names under one domain",
                 ["Use of the UDP protocol on port 53 together with recursive lookups to a resolver", "Queries being sent to the internal resolver and receiving a normal response", "The presence of DNS packets that cross the firewall from workstation clients"],
                 ["Every DNS query, benign or not, shares the options that are wrong here."],
                 "Normal lookups use short, dictionary-like names repeated often; tunnels use long random labels, once each, all under one domain.", rng),
        choice_q("l2q7", "Host %s looks up long hex-like names such as d3f9...cdn.example.net. Why is that less suspicious than the tunnel?" % t["cdn_host"],
                 "Only a few names, ordinary A queries, and no data-sized labels or TXT lookups",
                 ["Hex-looking names are never malicious, so they can be ignored in any capture", "CDN hostnames are always short, so any long name must mean tunneling", "Because the host queries the internal resolver rather than an external one"],
                 ["Compare how many names, which record type, and how long the labels are."],
                 "Content delivery networks do use random-looking hostnames, so name randomness alone causes false positives; volume, record type, and label length separate them.", rng),
    ]
    walk = [
        "Step 1 - Filter dns.qry.type == 16: most hosts send nothing or a few lookups; %s sends %d TXT queries." % (t["infected_ip"], t["n_tunnel_queries"]),
        "Step 2 - Look at the names: 0000.(46 data characters).%s, 0001.(46 data characters).%s ... The first label is a counter; the second is Base32-encoded data." % (t["domain"], t["domain"]),
        "Step 3 - Decode: extract the names, sort by counter, join the data labels, Base32-decode. The result starts with 'FILE:%s' and contains %d bytes of payroll-style records." % (t["filename"], t["secret_bytes"]),
        "Step 4 - Rule out decoys: %s looks up CDN-style names with ordinary A queries; %s makes a few legitimate TXT (SPF/DMARC) lookups." % (t["cdn_host"], t["mail_host"]),
        "Detection logic: alert on many unique subdomains under one parent domain, long labels, high character entropy, and unusual TXT volume per client. Mitigation: force clients through an internal resolver, monitor/rate-limit it, block newly registered or uncategorized domains, and use DNS security (RPZ) feeds.",
    ]
    return {"id": "lab2", "title": "Lab 2: Exfiltration through DNS", "layer": "Application (DNS over UDP)",
            "pcap": "pcaps/lab2_dns_tunnel.pcap",
            "intro": ["Six workstations send all DNS queries to the LAN resolver 10.20.0.2, and the firewall allows that traffic. Your DNS logs show one client making an unusual number of long TXT lookups. The capture covers 10 minutes.",
                      "Goal: find the host, the domain it talks to, and recover what it is sending."],
            "questions": qs, "walkthrough": walk}


# ------------------------------------------------------------------- Lab 3
def build_lab3(t, seed):
    rng = random.Random(seed + 13)
    inf, srv = "INFECTED_IP", "SERVER_IP"
    qs = [
        text_q("l3q1", "Which internal host is sending ICMP echo requests with unusual payloads?", [t["infected_ip"]],
               ["Filter icmp.type == 8 (echo requests) and add data.len as a column (right-click the Data length field > Apply as Column).",
                "Standard pings show a data length of 32 (Windows) or 40 (Linux, where Wireshark shows a separate timestamp field). Look for a host sending many different sizes."],
               "One host sends dozens of echo requests whose payload size changes every time."),
        text_q("l3q2", "What is the IP address of the remote tunnel endpoint?", [t["server_ip"]],
               ["Look at the Destination column of the odd-sized requests.", "Statistics > Conversations > IPv4 shows who talked to whom and how many packets."],
               "This external address answers every request with data of its own."),
        num_q("l3q3", "How many echo requests did the infected host send to that endpoint?", [t["n_requests"]],
              ["Count requests only (type 8), not replies.",
               "Filter icmp.type == 8 && ip.src == %s && ip.dst == %s and read the Displayed count." % (inf, srv)],
              "Each request carries one chunk of tunnel data."),
        num_q("l3q4", "What is the largest ICMP data length (in bytes) in any of the infected host's echo requests?", [t["max_payload"]],
              ["Filter icmp.type == 8 && ip.src == %s with data.len as a column, then sort that column descending." % inf,
               "data.len is the length of the ICMP payload only, not the whole IP packet (which is 28 bytes more)."],
              "A normal ping never varies like this; custom payload sizes are a strong anomaly."),
        text_q("l3q5", "Decode the first request (lowest ICMP sequence number) from the infected host. What shell command did the attacker send?",
               [t["first_cmd"]],
               ["The payload begins with the 4 characters 'TNL1' and the rest is Base64 text. Select the Data field, right-click > Copy > ...as Printable Text.",
                "Remove 'TNL1' and decode the remaining text, for example: echo 'TEXT' | base64 -d"],
               "This is the attacker running a command on the infected host through the ping channel; the reply contains the output."),
        choice_q("l3q6", "In a normal ping, how does the echo reply's data relate to the request's data?",
                 "The reply returns exactly the same data as the request",
                 ["The reply always carries a fresh random value chosen by the replying host", "The reply is always empty because only the request carries any data", "The reply contains the replying host's name and the current time"],
                 ["Compare the Data bytes of one request and its reply for any of the normal pings."],
                 "Because the reply must echo the request's data, any reply that carries different data is a clear sign of a covert channel.", rng),
        choice_q("l3q7", "Host %s sends 1400-byte pings. Why is that NOT the tunnel?" % t["mtu_host"],
                 "The payload is a fixed repeating pattern and each reply echoes it back unchanged",
                 ["Pings larger than 1000 bytes are always legitimate, so they can be ignored", "The host pings a private address, which attackers never use for tunneling", "It uses a different ICMP type, so it cannot carry any hidden data"],
                 ["Open one request and its reply and compare their data."],
                 "Large pings are used for MTU testing. Size alone is not enough; what matters is that the data never changes and the replies are identical.", rng),
    ]
    walk = [
        "Step 1 - Filter icmp.type == 8 with data.len as a column. Normal hosts send fixed sizes (32, 56, or a 1400-byte MTU test). %s sends %d requests of changing sizes (up to %d bytes) to %s." % (t["infected_ip"], t["n_requests"], t["max_payload"], t["server_ip"]),
        "Step 2 - Compare request and reply data. Normal pings return identical data; here the replies contain different data. All requests use the same ICMP identifier (0x1337).",
        "Step 3 - Decode the data. Each payload is 'TNL1' + Base64. The first request decodes to '%s', and its reply is a file listing." % t["first_cmd"],
        "Step 4 - Rule out the decoy. %s sends 1400-byte pings, but the payload is a fixed pattern echoed back unchanged." % t["mtu_host"],
        "Detection logic: flag echo requests with non-standard or varying payload sizes, replies that do not match requests, and unusually many ICMP packets to one external host. Mitigation: egress-filter ICMP (allow only to needed destinations), cap payload size and rate, and inspect ICMP at the firewall/IDS.",
    ]
    return {"id": "lab3", "title": "Lab 3: Covert channel in ICMP", "layer": "Network (ICMP over IP)",
            "pcap": "pcaps/lab3_icmp_tunnel.pcap",
            "intro": ["The firewall lets ICMP echo (ping) through so staff can troubleshoot. Flow logs show a workstation sending an unusual number of large, odd-sized echo packets to an external address. The capture covers 10 minutes.",
                      "Goal: identify the covert channel and recover what the attacker sent through it."],
            "questions": qs, "walkthrough": walk}


# ------------------------------------------------------------------- Lab 0
def build_lab0(t, seed):
    rng = random.Random(seed + 10)
    inf, c2 = t["infected_ip"], t["c2_ip"]
    steps = [
        {"title": "Open the capture and get oriented",
         "do": "Open lab0_tutorial.pcap in Wireshark, then choose Statistics > Capture File Properties.",
         "expect": "About 4 minutes of traffic and %d packets. Almost every packet is TCP on port 443 (HTTPS)." % t["packets"]},
        {"title": "See what you cannot read",
         "do": "Click a packet whose Protocol column says TLS and expand Transport Layer Security in the packet details. Then apply the display filter tls.handshake.type == 1 (ClientHello packets only) and expand the server_name extension in one of them.",
         "expect": "The data in 'Application Data' records is encrypted, but the ClientHello names the site in clear text. Everything else you will use is metadata: who talks to whom, when, and how much."},
        {"title": "Find who talks the most",
         "do": "Clear the filter. Open Statistics > Conversations, choose the IPv4 tab, and click the Packets column header twice to sort the largest first.",
         "expect": "The top row is %s <-> %s with %d packets. The next largest pair has only %d. One host exchanging far more traffic with one server is a lead, not proof." % (inf, c2, t["pair_packets"], t["next_pair_packets"])},
        {"title": "Count the connections",
         "do": "Apply the display filter tcp.flags.syn == 1 && tcp.flags.ack == 0. This keeps only the first packet of each new TCP connection. Look at the Source and Destination columns.",
         "expect": "%s opened %d separate connections to %s. Every other pair opened at most %d. Real people browse in bursts; this host reconnects over and over to the same server." % (inf, t["n_beacons"], c2, t["next_pair_connections"])},
        {"title": "Measure the timing",
         "do": "Apply ip.dst == %s && tcp.flags.syn == 1 && tcp.flags.ack == 0. Click a packet, expand Frame, right-click Time delta from previous displayed frame, and choose Apply as Column." % c2,
         "expect": "The new column reads %d seconds between every connection. Software runs on timers; people do not click on a perfect schedule. This is the signature of a beacon (Lab 1 adds random jitter to hide it)." % t["interval"]},
        {"title": "Measure the sizes",
         "do": "Change the filter to ip.addr == %s. Open Statistics > Conversations, choose the TCP tab, and tick Limit to display filter." % c2,
         "expect": "Every row is identical: %d packets and %d bytes in total. Normal browsing varies a lot from page to page; a program sending the same small message each time does not." % (t["conn_frames"], t["conn_bytes"])},
        {"title": "Put it together",
         "do": "Write down the host, the server, the interval, and the sizes.",
         "expect": "Infected host %s, C2 server %s, a check-in every %d s, identical sizes. The method: (1) find the pair that stands out, (2) measure timing, (3) measure sizes, (4) check the destination. Labs 1-3 repeat it with harder data: jitter, decoys, and other protocols." % (inf, c2, t["interval"])},
    ]
    qs = [
        text_q("l0q1", "Checkpoint 1: Which internal IP address is the infected host?", [inf],
               ["Step 3 and step 4 of the worked example show how to find it."],
               "It is the host that opened %d connections to one server." % t["n_beacons"]),
        text_q("l0q2", "Checkpoint 2: What is the IP address of the C2 server?", [c2],
               ["It is the server the infected host keeps reconnecting to (step 4)."],
               "Only the beaconing host talks to it this often."),
        num_q("l0q3", "Checkpoint 3: How many seconds pass between check-ins?", range(t["interval"] - 1, t["interval"] + 2),
              ["Step 5 shows how to add the time-delta column."],
              "The gap is a constant %d s. Real malware adds jitter, which you will meet in Lab 1." % t["interval"]),
    ]
    return {"id": "lab0", "nav": "Tutorial", "title": "Tutorial: Find a beacon (worked example)",
            "layer": "Transport / Application (TCP, TLS)", "pcap": "pcaps/lab0_tutorial.pcap",
            "intro": ["Start here. This short capture has one obvious pattern, so you can learn the method before the real labs. Follow the steps in order in Wireshark, then answer three checkpoint questions to confirm you got it.",
                      "You need Wireshark and the capture below. No threat-hunting experience is needed."],
            "steps": steps, "questions": qs, "walkthrough": []}


PRELAB = {
    "lab1": [
        {"h": "What a TLS connection looks like", "p": "Every HTTPS connection starts with a TCP handshake and then a TLS handshake. The client's first TLS message (the ClientHello) names the website it wants (the SNI) in clear text. After the handshake everything is 'Application Data' that you cannot read. What you can still see is when each connection starts, how many bytes go each way, and which address it goes to."},
        {"h": "What is beaconing?", "p": "Malware waiting for instructions checks in with its command-and-control (C2) server on a timer. Software works on schedules; people do not. Attackers often add jitter (random variation) to hide the pattern, so look for roughly regular timing rather than perfectly regular timing."},
        {"h": "Wireshark tools you will use", "p": "Statistics > Conversations (one row per address pair or connection; tick Limit to display filter to look at one server). The display filter tcp.flags.syn == 1 && tcp.flags.ack == 0 shows only new connections. To see gaps between packets, expand Frame in the packet details, right-click Time delta from previous displayed frame, and choose Apply as Column."},
        {"h": "New to this?", "p": "Do the Tutorial first. It walks through the same steps on a simpler capture."},
    ],
    "lab2": [
        {"h": "How a DNS name is built", "p": "A name such as www.example.org is read from right to left: org, then example, then www. Each part is a label (at most 63 bytes) and the whole name is at most 255 bytes. Names are not case-sensitive. Normal names are short and readable."},
        {"h": "Record types", "p": "A and AAAA queries ask for IPv4 and IPv6 addresses and make up most DNS traffic. TXT queries ask for free text (email policies such as SPF and DMARC use them), so a TXT record can also carry arbitrary data."},
        {"h": "How DNS tunneling works", "p": "An attacker who runs a DNS domain receives data as the query names themselves. The infected host encodes the data into the labels of a name under that domain (using a DNS-safe encoding such as Base32, because names are not case-sensitive) and the attacker's name server reads the names. Replies can carry data back. The firewall only sees ordinary DNS."},
        {"h": "Wireshark tools you will use", "p": "Filters: dns.flags.response == 0 (queries only), dns.qry.type == 16 (TXT), and dns.qry.name contains \"text\". Add the column dns.qry.name.len (right-click the field > Apply as Column) to see name lengths. The Displayed count in the status bar tells you how many packets match."},
        {"h": "Decoding", "p": "One question asks you to decode the stolen data. Copy the names from Wireshark or export them with tshark (the hints show how) and decode them with a few lines of Python."},
    ],
    "lab3": [
        {"h": "How ping works", "p": "Ping sends an ICMP Echo Request (type 8) and the target answers with an Echo Reply (type 0). The request carries a data field, and the reply must send the same data back."},
        {"h": "What normal pings look like", "p": "Windows sends 32 bytes of data (abcdefg...). Linux sends 56 bytes (a timestamp plus a pattern); Wireshark shows the timestamp separately, so its data length shows 40. Normal pings repeat the same size at steady intervals. Some administrators send large pings to test the maximum packet size (MTU)."},
        {"h": "How ICMP tunneling works", "p": "Firewalls usually let ping through, so malware can place its own data in the data field of echo requests and the server can answer with data in the replies. ICMP has no ports, so the attacker uses the identifier and sequence number fields to keep the conversation together."},
        {"h": "Wireshark tools you will use", "p": "Filter icmp.type == 8 for requests or icmp.type == 0 for replies, and add the column data.len to see payload sizes. To compare a request with its reply, click each one and compare the Data bytes."},
    ],
}


def _with_prelab(fn, key):
    def wrapper(t, seed):
        lab = fn(t, seed)
        lab["prelab"] = PRELAB[key]
        return lab
    return wrapper


build_lab1 = _with_prelab(build_lab1, "lab1")
build_lab2 = _with_prelab(build_lab2, "lab2")
build_lab3 = _with_prelab(build_lab3, "lab3")


def build_quiz(seed):
    rng = random.Random(seed + 14)
    qs = [
        choice_q("fq1", "At which TCP/IP layer does DNS tunneling operate?", "Application layer",
                 ["Link layer", "Internet (network) layer", "Transport layer"], ["DNS is a protocol that runs on top of UDP."],
                 "DNS is an application-layer protocol; the attacker abuses it, not UDP or IP.", rng),
        choice_q("fq2", "ICMP tunneling hides data in a protocol of which TCP/IP layer?", "Internet (network) layer, carried directly in IP",
                 ["Application layer protocols such as HTTP", "Transport layer (TCP or UDP ports)", "Link layer (Ethernet frames)"], ["ICMP is carried directly inside IP packets."],
                 "ICMP is carried directly in IP, so it belongs to the Internet layer.", rng),
        choice_q("fq3", "An HTTPS beacon's payload is encrypted. Which layer's behavior still reveals it?",
                 "Transport layer connection timing and sizes",
                 ["The decrypted application-layer payload itself", "Link-layer (MAC) addresses of the sender", "The TLS session keys held by the client"],
                 ["Think about connection start times and byte counts."],
                 "TCP connection timing and byte counts stay visible even when TLS hides the content.", rng),
        choice_q("fq4", "Best single mitigation for DNS tunneling?",
                 "Force clients through an internal resolver and monitor or rate-limit unusual TXT and long-name queries",
                 ["Block all UDP traffic at the border firewall so that no DNS packets of any kind can leave the network", "Disable DNS on all client machines and rely on hard-coded IP addresses for every connection instead", "Encrypt every DNS query with a key that only the client machine holds, so nothing can be inspected"],
                 ["The mitigation must keep normal DNS working."],
                 "Central resolver control plus analytics can catch tunnels without breaking DNS.", rng),
        choice_q("fq5", "Best mitigation for ICMP tunneling?",
                 "Limit ICMP at the egress firewall by destination, payload size, and rate",
                 ["Block TCP port 443 on the egress firewall so web traffic cannot leave", "Turn off logging on all gateways to reduce load from ping traffic", "Allow all ICMP traffic so that troubleshooting always works"],
                 ["Ping is useful, so allow only what is needed."],
                 "Egress filtering with size and rate limits keeps ping useful but stops bulk data.", rng),
        choice_q("fq6", "Best mitigation for HTTPS C2 beaconing?",
                 "Allow-list egress destinations or use a TLS-inspecting proxy, plus alerts on low-variance periodic connections",
                 ["Block outbound DNS on the firewall so that the implant can no longer look up the address of its server", "Use much longer TCP timeouts on the gateway so that idle connections are never closed by the network", "Switch every workstation to plain HTTP so that the traffic is easier for the security team to read"],
                 ["Defenders need visibility into destinations and behavior."],
                 "Control where hosts may connect and watch for machine-like regularity.", rng),
    ]
    return {"id": "quiz", "title": "Final Quiz: Layers and Defenses", "layer": "All", "pcap": None,
            "intro": ["Map each attack to its TCP/IP layer and pick the best defense."], "questions": qs, "walkthrough": []}
