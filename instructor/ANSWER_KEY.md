# Answer Key (seed 530)

Instructor copy. Do not publish with the student page.

## Tutorial: Find a beacon (worked example)

1. Checkpoint 1: Which internal IP address is the infected host?
   - **Answer:** 10.20.0.22
   - Why: It is the host that opened 14 connections to one server.
2. Checkpoint 2: What is the IP address of the C2 server?
   - **Answer:** 203.0.113.88
   - Why: Only the beaconing host talks to it this often.
3. Checkpoint 3: How many seconds pass between check-ins?
   - **Answer:** 14-16
   - Why: The gap is a constant 15 s. Real malware adds jitter, which you will meet in Lab 1.

## Lab 1: Beaconing inside HTTPS

1. Which internal IP address belongs to the infected host?
   - **Answer:** 10.20.0.21
   - Why: One internal host opened about 29 connections to the same external address; no other host/server pair comes close.
2. What is the IP address of the command-and-control (C2) server?
   - **Answer:** 203.0.113.110
   - Why: Connections to this address repeat on a steady schedule; browsing traffic does not.
3. How many TCP connections did the infected host open to the C2 server?
   - **Answer:** 29
   - Why: The implant opens one short connection per check-in, so the connection count equals the number of beacons.
4. Roughly how many seconds pass between beacons? (Give a whole number of seconds.)
   - **Answer:** 53-66
   - Why: About 60 s with roughly +/-10% jitter (observed 54-65 s). Jitter is meant to defeat detection that looks for an exact interval.
5. One check-in was different: the C2 server sent back a much larger response (a tasking). What was the infected host's TCP port on that connection?
   - **Answer:** 53346
   - Why: Quiet check-ins are tiny and nearly identical in size. The single large reply is the C2 handing out a task.
6. Even though the session is encrypted, which server name (SNI) does the infected host send in its TLS ClientHello?
   - **Answer:** api.cloudmetrics.example
   - Why: TLS 1.3 without ECH still exposes the SNI. It names a plausible-looking 'metrics' service.
7. Host 10.20.0.25 also connects to 198.51.100.77 on a regular schedule (about every 5 minutes). Why is it NOT the malware?
   - **Answer:** Its request and response sizes vary a lot, unlike the near-identical sizes of the beacon.
   - Why: Regularity is a lead, not a verdict. A mail client polls on a timer too, but its payload sizes follow the mailbox contents; the beacon's sizes barely move.
8. The payload is encrypted. Which combination of observable features can still expose the beacon?
   - **Answer:** Timing, sizes, and destination (including the SNI)
   - Why: Encryption hides content, not metadata. Defenders hunt with timing, size, and destination.

**Walkthrough**

- Step 1 - Find the pair. Statistics > Conversations > TCP: the pair 10.20.0.21 <-> 203.0.113.110 has 29 connections; every other pair has only a handful.
- Step 2 - Measure timing. Filter ip.dst == 203.0.113.110 && tcp.flags.syn == 1 && tcp.flags.ack == 0 and add frame.time_delta_displayed: about 60 s apart (observed 54-65 s), i.e. 60 s with ~10% jitter.
- Step 3 - Measure sizes. Every check-in transfers almost the same number of bytes in each direction (a ~280-byte request and ~165-byte reply after the handshake). Check-in #17 breaks the pattern: the server sends about 4.3 KB more than usual (a task), and the next check-in uploads about 1.9 KB (the result). In Statistics > Conversations, these are the two outlier rows among near-identical ones.
- Step 4 - Rule out the decoy. 10.20.0.25 polls 198.51.100.77 about every 300 s, but its sizes vary widely, so it is a mail client, not an implant.
- Detection logic: group connections by (source, destination); look for low variance in inter-arrival time and in bytes per connection; then check the destination's reputation and the SNI. Mitigation: egress allow-listing or a TLS-inspecting proxy, plus beacon-analytics alerts on low-variance periodic connections.

## Lab 2: Exfiltration through DNS

1. Which internal host is tunneling data over DNS?
   - **Answer:** 10.20.0.22
   - Why: One host sends many long, random-looking TXT queries to a single domain.
2. Which domain are the tunnel queries sent to?
   - **Answer:** metrics-sync.example
   - Why: Every tunnel query ends in the attacker's domain; its authoritative server receives the data.
3. How many DNS queries (not responses) were sent to that domain?
   - **Answer:** 117
   - Why: Each query carries one 46-character chunk of the file, so the count tells you roughly how much data left.
4. Which DNS record type does the tunnel use?
   - **Answer:** TXT
   - Why: TXT records can carry arbitrary text, so tunneling tools favor them; the replies carry data back.
5. Decode the exfiltrated data. What is the name of the file being stolen? (It appears at the very start of the decoded data.)
   - **Answer:** payroll_q3.csv
   - Why: Base32-decoding the joined labels gives the start of a CSV file: 'FILE:payroll_q3.csv' followed by employee records.
6. Which pair of features best separates the tunnel from normal DNS?
   - **Answer:** Long, high-entropy subdomains with a very large number of unique names under one domain
   - Why: Normal lookups use short, dictionary-like names repeated often; tunnels use long random labels, once each, all under one domain.
7. Host 10.20.0.21 looks up long hex-like names such as d3f9...cdn.example.net. Why is that less suspicious than the tunnel?
   - **Answer:** Only a few names, ordinary A queries, and no data-sized labels or TXT lookups
   - Why: Content delivery networks do use random-looking hostnames, so name randomness alone causes false positives; volume, record type, and label length separate them.

**Walkthrough**

- Step 1 - Filter dns.qry.type == 16: most hosts send nothing or a few lookups; 10.20.0.22 sends 117 TXT queries.
- Step 2 - Look at the names: 0000.(46 data characters).metrics-sync.example, 0001.(46 data characters).metrics-sync.example ... The first label is a counter; the second is Base32-encoded data.
- Step 3 - Decode: extract the names, sort by counter, join the data labels, Base32-decode. The result starts with 'FILE:payroll_q3.csv' and contains 3341 bytes of payroll-style records.
- Step 4 - Rule out decoys: 10.20.0.21 looks up CDN-style names with ordinary A queries; 10.20.0.24 makes a few legitimate TXT (SPF/DMARC) lookups.
- Detection logic: alert on many unique subdomains under one parent domain, long labels, high character entropy, and unusual TXT volume per client. Mitigation: force clients through an internal resolver, monitor/rate-limit it, block newly registered or uncategorized domains, and use DNS security (RPZ) feeds.

## Lab 3: Covert channel in ICMP

1. Which internal host is sending ICMP echo requests with unusual payloads?
   - **Answer:** 10.20.0.21
   - Why: One host sends dozens of echo requests whose payload size changes every time.
2. What is the IP address of the remote tunnel endpoint?
   - **Answer:** 203.0.113.28
   - Why: This external address answers every request with data of its own.
3. How many echo requests did the infected host send to that endpoint?
   - **Answer:** 61
   - Why: Each request carries one chunk of tunnel data.
4. What is the largest ICMP data length (in bytes) in any of the infected host's echo requests?
   - **Answer:** 856
   - Why: A normal ping never varies like this; custom payload sizes are a strong anomaly.
5. Decode the first request (lowest ICMP sequence number) from the infected host. What shell command did the attacker send?
   - **Answer:** ls /var/backups
   - Why: This is the attacker running a command on the infected host through the ping channel; the reply contains the output.
6. In a normal ping, how does the echo reply's data relate to the request's data?
   - **Answer:** The reply returns exactly the same data as the request
   - Why: Because the reply must echo the request's data, any reply that carries different data is a clear sign of a covert channel.
7. Host 10.20.0.23 sends 1400-byte pings. Why is that NOT the tunnel?
   - **Answer:** The payload is a fixed repeating pattern and each reply echoes it back unchanged
   - Why: Large pings are used for MTU testing. Size alone is not enough; what matters is that the data never changes and the replies are identical.

**Walkthrough**

- Step 1 - Filter icmp.type == 8 with data.len as a column. Normal hosts send fixed sizes (32, 56, or a 1400-byte MTU test). 10.20.0.21 sends 61 requests of changing sizes (up to 856 bytes) to 203.0.113.28.
- Step 2 - Compare request and reply data. Normal pings return identical data; here the replies contain different data. All requests use the same ICMP identifier (0x1337).
- Step 3 - Decode the data. Each payload is 'TNL1' + Base64. The first request decodes to 'ls /var/backups', and its reply is a file listing.
- Step 4 - Rule out the decoy. 10.20.0.23 sends 1400-byte pings, but the payload is a fixed pattern echoed back unchanged.
- Detection logic: flag echo requests with non-standard or varying payload sizes, replies that do not match requests, and unusually many ICMP packets to one external host. Mitigation: egress-filter ICMP (allow only to needed destinations), cap payload size and rate, and inspect ICMP at the firewall/IDS.

## Final Quiz: Layers and Defenses

1. At which TCP/IP layer does DNS tunneling operate?
   - **Answer:** Application layer
   - Why: DNS is an application-layer protocol; the attacker abuses it, not UDP or IP.
2. ICMP tunneling hides data in a protocol of which TCP/IP layer?
   - **Answer:** Internet (network) layer, carried directly in IP
   - Why: ICMP is carried directly in IP, so it belongs to the Internet layer.
3. An HTTPS beacon's payload is encrypted. Which layer's behavior still reveals it?
   - **Answer:** Transport layer connection timing and sizes
   - Why: TCP connection timing and byte counts stay visible even when TLS hides the content.
4. Best single mitigation for DNS tunneling?
   - **Answer:** Force clients through an internal resolver and monitor or rate-limit unusual TXT and long-name queries
   - Why: Central resolver control plus analytics can catch tunnels without breaking DNS.
5. Best mitigation for ICMP tunneling?
   - **Answer:** Limit ICMP at the egress firewall by destination, payload size, and rate
   - Why: Egress filtering with size and rate limits keeps ping useful but stops bulk data.
6. Best mitigation for HTTPS C2 beaconing?
   - **Answer:** Allow-list egress destinations or use a TLS-inspecting proxy, plus alerts on low-variance periodic connections
   - Why: Control where hosts may connect and watch for machine-like regularity.
