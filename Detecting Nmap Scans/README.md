# 🎯 Project 04: Detecting Nmap Scans with Suricata

## 📋 Overview

Project 01 confirmed Suricata's default ET/open ruleset catches SYN and XMAS scans. This project extends that testing across all six major Nmap scan types, running each one live against my Windows 10 VM and checking exactly what fired (or didn't) in `eve.json`. I also wanted to see whether my custom NULL scan rule from Project 02 (SID 1000004) would hold up as the only detection for that scan type, or whether ET/open already had it covered.

## 🖥️ Lab Setup

- Kali Linux VM (192.168.56.102), Suricata 8.0.5, dual interface (eth0 Host-Only + eth1 NAT)
- Windows 10 VM (192.168.56.101) as scan target
- Ruleset: et/open + aleksibovellan/nmap + my custom `local.rules` (from Project 02), 50,912 rules total
- Each scan run individually with a timestamped `date` command before it, so every alert in `eve.json` could be attributed to the correct scan by timing

## 🔍 Test Results

| Scan Type | Nmap Flag | Alert Fired | Signature | Detected? |
|---|---|---|---|---|
| 🔓 SYN | `-sS` | SID 3400001 / 3400002 | POSSBL PORT SCAN (NMAP -sS) | ✅ Yes |
| 🕳️ NULL | `-sN` | SID 1000004 | CUSTOM Nmap NULL Scan Detected | ✅ Yes (custom rule only) |
| 🎄 FIN | `-sF` | None | — | ❌ No |
| 🎄 XMAS | `-sX` | SID 3400005 | POSSBL PORT SCAN (NMAP -sX) | ✅ Yes |
| ✅ ACK | `-sA` | SID 3400004 | POSSBL PORT SCAN (NMAP -sA) | ✅ Yes |
| 🤝 Connect | `-sT` | None | — | ❌ No |

## 📊 Scan-by-Scan Detail

### 🔓 SYN Scan — Detected
Started at 14:53:12, alerts began firing 14:53:17 and continued in rapid succession (over 100 individual alerts) as Nmap swept all 1000 ports. ET/open's SID 3400001 and 3400002 both fired throughout the scan, confirming the built-in ruleset handles standard SYN scans without any custom rule needed.

### 🕳️ NULL Scan — Detected (Custom Rule Only)
Started at 14:54:31, my custom SID 1000004 began firing at 14:54:32.204 and continued for the full ~22-second scan duration. This is the result I was most interested in: no ET/open signature fired for this scan type at all. My custom rule from Project 02 was the only thing standing between this scan and silent passage through the network. That validates the reasoning behind writing it in the first place.

### 🎄 FIN Scan — Not Detected
Started at 14:54:57. No alerts of any kind appear in `eve.json` for the full ~22-second scan window. This is a real gap. My custom NULL scan rule only matches on `flags:0` (no flags set), and FIN scans set the FIN flag, so it doesn't overlap. ET/open apparently has no default signature for FIN scans in this ruleset either. This is a legitimate detection blind spot in my current lab, not something the data glosses over.

### 🎄 XMAS Scan — Detected
Started at 14:55:25, SID 3400005 began firing almost immediately at 14:55:26.452 and continued for the ~10-second scan. ET/open covers this one directly.

### ✅ ACK Scan — Detected
Started at 14:55:54, SID 3400004 fired starting at 14:55:56.255 and continued through the roughly 21-second scan duration. Also covered by ET/open.

### 🤝 Connect Scan — Not Detected
Started at 14:56:21. No alerts appear in `eve.json` for this scan at all. This makes sense on reflection: a TCP connect scan completes the full three-way handshake on every port, so from a packet-inspection standpoint it looks like normal, legitimate connection attempts rather than the malformed or unusual flag combinations that trigger scan-detection signatures. Distinguishing it from real traffic would require a connection-rate or fan-out heuristic rather than a flag-based signature, which is a different category of rule than the ones I've written so far.

## 🧠 What I Learned

The biggest takeaway is that "my ruleset caught 4 out of 6 scan types" is a more useful and more honest result than it might first appear. The FIN scan gap in particular shows that a flags-based custom rule only covers the specific flag pattern it was written for; a rule that only checks `flags:0` will never catch a FIN scan just because both are "unusual" scan types. If I wanted full coverage, that would mean writing a distinct FIN scan rule rather than assuming the NULL scan rule generalizes. The connect scan result was the most conceptually interesting: it's a reminder that not every attack technique looks anomalous at the packet level, and that some detection problems (like connect scan visibility) need a completely different detection strategy such as rate-based or behavioral rules rather than signature matching on flags.

## 🎯 SOC Relevance

Running every scan type live rather than assuming ruleset coverage is exactly the kind of validation a SOC analyst should be doing before trusting a detection stack in production. A ruleset that silently misses FIN scans and connect scans is a real gap an attacker could exploit, and knowing precisely where that gap is (and why) is far more valuable than a vague sense that "scans are covered." This kind of scan-by-scan verification is also good practice for writing accurate detection coverage documentation, which is something SOC teams maintain to know exactly what their tooling does and doesn't catch.

## 🗺️ MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Network Service Discovery | T1046 |
| Network Sniffing (packet-level scan visibility) | T1040 |

## ⏭️ Next Steps

Moving on to Project 05: Splunk Integration Dashboard, building a unified view across the Suricata alerts confirmed in Projects 01-04 alongside the Zeek and Wireshark findings from earlier repos. I may also revisit the FIN scan gap here by writing a targeted custom rule (`flags:F`) once the dashboard work is further along.
