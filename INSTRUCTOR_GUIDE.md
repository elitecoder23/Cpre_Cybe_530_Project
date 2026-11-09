# Instructor Guide

## Purpose and objectives

Students practice finding attacks that hide in encrypted or trusted protocols using only metadata.
After the labs they should be able to:

1. Identify C2 beaconing in an encrypted HTTPS capture from timing and size (Lab 1).
2. Distinguish DNS tunneling from normal DNS using name length, uniqueness, and volume (Lab 2).
3. Detect ICMP tunneling and, for all three attacks, name the TCP/IP layer and one mitigation (Lab 3 and final quiz).

Prerequisite: the course Wireshark and ping labs (display filters, Follow Stream, Statistics menus).
The labs build on them but are about spotting hidden malicious behavior, not recognizing normal traffic.

## Structure of each lab

Tutorial: short easy capture, seven numbered steps (Do / You should see) and three checkpoint questions.
Labs 1-3: "Before you start" notes (what normal traffic looks like, how the attack works, which Wireshark tools to use), a capture, 7-8 questions with two hints each, and a walkthrough.

## Running the labs

- Give students the hosted page (or `web/index.html` plus the `web/pcaps` folder). Nothing is uploaded; scores stay in the student's browser.
- Have students start with the Tutorial (a worked example with exact Wireshark steps) and read the "Before you start" notes in each lab.
- Suggested pacing (estimates, to be confirmed by testing): Tutorial about 15-20 min, Lab 1 about 30-40 min, Lab 2 about 30-40 min, Lab 3 about 25-30 min, quiz about 10 min.
- Grading: the page shows correct answers and hints used. Ask students to submit a screenshot of the score line, or use `generate.py --seed N` to give each section its own variant.
- Do not publish `instructor/` (answer key and ground truth). Publish only `web/`.

## Making a new variant

```bash
python generate.py --seed 42
python verify.py          # confirms every answer against the new captures
```

A new seed changes the infected host, server IPs, timings, sizes, decoy hosts, and every answer. It rewrites
`web/pcaps/*`, `web/labdata.js`, and `instructor/*`.

## Detection logic (what each lab teaches)

| Attack | Observable | Why it works |
|---|---|---|
| HTTPS beaconing | One host reconnects to one server on a fixed schedule (~60 s, jitter ~10%); per-connection byte totals are almost identical; one outlier pair (task + result) | Machines are more regular than people; encryption hides content, not timing/size |
| DNS tunneling | One host sends hundreds of unique, long (46-char), Base32-looking names under one domain, all TXT | Data must be encoded into names; names become long and random |
| ICMP tunneling | Varying echo payload sizes to one external host; reply data differs from request data; constant ICMP id | A normal ping echoes its data back unchanged and uses a standard size |

Decoys teach that one signal is not a verdict: a mail client has regular timing (Lab 1), a CDN has random-looking
hostnames (Lab 2), and an MTU test uses large pings (Lab 3).

## Mitigations covered

- Beaconing: allow-list egress destinations or TLS-inspecting proxy; alert on low-variance periodic connections.
- DNS tunneling: force clients through an internal resolver; rate-limit/alert on long, high-entropy, TXT-heavy queries; block newly registered domains.
- ICMP tunneling: egress-filter ICMP by destination, payload size, and rate; inspect ICMP at the firewall/IDS.

## Answer key

`instructor/ANSWER_KEY.md` lists every question, its answer, an explanation, and the lab walkthrough.
`instructor/ground_truth.json` holds the raw generator output.

## Notes and limits

- Answer checking is client-side (salted SHA-256), so a student reading the page source can find answers.
- The TLS in Lab 1 is structurally valid but not real cryptography; it is fine for metadata analysis but cannot be decrypted.
- Wireshark shows the first 16 bytes of a Linux ping payload as a timestamp, so its `data.len` is 40 for a 56-byte payload.
