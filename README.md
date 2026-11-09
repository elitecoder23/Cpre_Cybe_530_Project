# Hunting What You Can't Read

CTF-style labs for detecting **encrypted and covert network traffic** using only metadata
(timing, packet size, entropy, volume, structure). Built for an undergraduate/graduate network security
course (CprE 5300). All traffic is synthetic.

| Lab | Threat | TCP/IP layer | What students learn to spot |
|---|---|---|---|
| 0 (tutorial) | An obvious beacon in a short, easy capture | Transport / Application | The method, step by step: find the standout pair, measure timing, measure sizes, check the destination |
| 1 | C2 beaconing inside HTTPS | Transport / Application | Regular intervals with jitter, near-identical connection sizes, one large "tasking" response |
| 2 | Data exfiltration through DNS tunneling | Application | Long Base32 subdomains, many unique names under one domain, TXT volume; decoding the stolen file |
| 3 | Covert channel in ICMP echo (ping) | Internet (network) | Custom/variable payload sizes, replies whose data differs from the request; decoding the first command |

Each lab opens with "Before you start" notes (background and the Wireshark tools needed). The tutorial is a worked example with exact Wireshark steps and what you should see at each one. A final quiz maps each attack to its layer and a defense.

## What is in this repo

```
generate.py            builds the PCAPs, the question data, and the answer key
labs/                  traffic generators (lab0_tutorial.py, lab1_beacon.py, lab2_dns.py, lab3_icmp.py, common.py)
questions.py           questions, hints, walkthroughs (answers stored as salted hashes)
verify.py              recomputes every answer from the PCAPs with tshark and tests the web checker
web/                   the student-facing static page (index.html, app.js, style.css, labdata.js)
web/pcaps/             the four generated captures (tutorial + three labs)
instructor/            ANSWER_KEY.md and ground_truth.json  (do NOT publish with the student page)
INSTRUCTOR_GUIDE.md    how to run, host, grade, and regenerate
```

## For students

1. Open `web/index.html` in a browser (or the hosted page). No install, no server.
2. New here? Start with the Tutorial and follow its steps. Read the "Before you start" notes at the top of each lab.
3. Download a lab's PCAP and open it in [Wireshark](https://www.wireshark.org/). Answer the questions. Each has up to two optional hints. Progress is saved in your browser only.
4. Read the walkthrough after finishing, then take the final quiz.

You need Wireshark and a browser. Lab 2 question 5 is easier with a few lines of Python (Base32 decoding).

## For instructors and developers

Requirements: Python 3.9+ and Scapy (`pip install -r requirements.txt`). `tshark` is only needed for `verify.py`.

```bash
python generate.py                # default seed 530: writes web/pcaps/*.pcap (tutorial + 3 labs), web/labdata.js, instructor/*
python generate.py --seed 7       # a new variant: different hosts, IPs, sizes, and answers
python verify.py                  # independent check of every answer (needs tshark and node)
```

Generation is deterministic: the same seed always produces the same captures and answers.
Host to a static site (for example GitHub Pages) by publishing the `web/` folder only.

## How the traffic is built

- **Lab 0 / Tutorial** (4 min, 3 hosts): ordinary browsing plus one host checking in with a C2 server every exactly 15 s with identical-size messages: no jitter and no decoy, so every step of the worked example has a clean result.
- **Lab 1** (30 min, 6 hosts): ordinary HTTPS browsing for everyone (Poisson arrivals, log-normal sizes);
  a decoy mail client polling every ~300 s with variable sizes; one infected host opening a new TLS
  connection to the C2 every 60 s +/-10%, with ~280-byte requests and ~165-byte replies, except one
  check-in where the server sends ~4.3 KB (a task) and the next uploads ~1.9 KB. TLS records
  (ClientHello with SNI, ServerHello, application data) are structurally valid so Wireshark dissects
  them, but the bodies are random bytes, not real encryption.
- **Lab 2** (10 min): ordinary A/AAAA lookups through the LAN resolver; a decoy host using long CDN-style
  names; a few legitimate TXT (SPF/DMARC) lookups; one infected host sending a fake CSV in 46-character
  Base32 chunks as `<seq>.<data>.metrics-sync.example` TXT queries.
- **Lab 3** (10 min): Windows (32-byte) and Linux (56-byte) pings, a decoy 1400-byte MTU test whose replies
  echo the request, and a tunnel with constant ICMP id 0x1337 and `TNL1` + Base64 payloads of varying size
  whose replies carry different data.

Addresses come from RFC 5737 documentation ranges and names from the reserved `.example` domain.

## Known limitations

- Answers are checked in the browser using salted SHA-256 hashes. This keeps answers out of plain sight
  but anyone who reads the page source can recover them; it is a learning tool, not a secure exam.
- Synthetic traffic is simpler and cleaner than real networks. The labs teach the concepts, not
  production detection tuning.
- Not implemented (future work): TLS client fingerprinting (JA3/JA4) and OT protocols such as Modbus/TCP.

## Sources

IETF RFC 1035 (DNS), RFC 792 (ICMP), RFC 9293 (TCP), RFC 5737 (documentation addresses);
MITRE ATT&CK T1572 (Protocol Tunneling); Scapy and Wireshark documentation; D. Jacobson,
*Introduction to Network Security* (CRC Press, 2008).
