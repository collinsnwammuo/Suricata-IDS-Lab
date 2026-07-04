# 🚨 Project 03: Live SSH Brute Force Detection with Suricata

## 📋 Overview

This project takes the custom SSH brute force rule I wrote in Project 02 (SID 1000001) and tests it against a real, live Hydra attack -- the same methodology I used in Splunk Project 11, but this time measuring Suricata's real-time packet inspection against Splunk's scheduled-search detection model. The goal was to get an honest Mean Time to Detect (MTTD) number and see how the two detection approaches actually compare.

## 🖥️ Lab Setup

- Kali Linux VM (192.168.56.102) running Suricata 8.0.5 and Hydra 9.6
- Windows 10 VM (192.168.56.101) as the SSH brute force target
- Both VMs on the Host-Only network (eth0), which Suricata is actively monitoring via af-packet
- Target rule: SID 1000001, `CUSTOM SSH Brute Force Attempt - Multiple Failed Connections`
- Alerts logged to `/var/log/suricata/eve.json`, ingested into Splunk under the `suricata` sourcetype and `soc_lab` index

## 🐛 First Attempt: The Rule Didn't Fire

My first live test used:

```bash
hydra -l kali -t 4 -P /home/kali/wordlist.txt ssh://192.168.56.101
```

Hydra ran 26 login attempts in about 3 seconds and finished with 0 valid passwords found, exactly as expected for a test wordlist. But no alert fired.

The problem was in how my rule was written. SID 1000001 was thresholding on new SYN packets:

```
threshold:type both, track by_src, count 10, seconds 60;
```

With `-t 4`, Hydra only opened 4 actual TCP connections and reused each one for roughly 7 password attempts apiece, since SSH allows multiple authentication tries per session before disconnecting. That meant only 4 SYN packets ever hit the wire, not the 10 my threshold required. I'd written the rule assuming password attempts and connection attempts were the same thing, and live traffic proved that assumption wrong.

## 🔧 Fixing the Rule

I tuned the threshold down to match how SSH brute force tools actually behave on the wire:

```
threshold:type both, track by_src, count 3, seconds 60;
```

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl restart suricata
```

This felt like the more honest fix rather than just cranking up Hydra's thread count to force a false positive-style pass. A real attacker running a fast SSH brute force won't necessarily open 10+ distinct connections either, so tuning the rule to reflect realistic connection behavior makes it more useful outside a lab, not just able to pass my own test.

## ✅ Second Attempt: Alert Fires

```bash
date
hydra -l kali -t 4 -P /home/kali/wordlist.txt ssh://192.168.56.101
```

```
Sat Jul  4 02:24:12 PM WAT 2026
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak
Hydra starting at 2026-07-04 14:24:12
[DATA] max 4 tasks per 1 server, overall 4 tasks, 26 login tries (l:1/p:26), ~7 tries per task
[DATA] attacking ssh://192.168.56.101:22/
1 of 1 target completed, 0 valid password found
Hydra finished at 2026-07-04 14:24:14
```

Alert from `eve.json`:

```json
{
  "timestamp": "2026-07-04T14:24:12.875263+0100",
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "192.168.56.102",
  "src_port": 49572,
  "dest_ip": "192.168.56.101",
  "dest_port": 22,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "signature_id": 1000001,
    "rev": 1,
    "signature": "CUSTOM SSH Brute Force Attempt - Multiple Failed Connections",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "direction": "to_server"
}
```

Source IP (192.168.56.102, my Kali box) and destination (192.168.56.101, the Windows 10 VM) match the attack exactly, confirming this wasn't a stray or unrelated alert.

## ⏱️ MTTD Result

| Event | Timestamp |
|---|---|
| Hydra attack started | 2026-07-04 14:24:12 |
| Suricata alert fired | 2026-07-04 14:24:12.875263 |
| **MTTD** | **~0.87 seconds** |

| Detection Method | MTTD |
|---|---|
| 🕐 Splunk scheduled search (Project 11) | 12 min 23 sec |
| ⚡ Suricata real-time IDS (Project 03) | ~0.87 sec |

Suricata inspects packets inline as they cross the wire, so detection happens almost the instant the threshold is crossed. Splunk's detection in Project 11 depended on a scheduled correlation search running every 5 minutes, which is why its MTTD was measured in minutes instead of fractions of a second. This isn't really a knock against Splunk -- it's a difference in architecture. Inline packet inspection and scheduled log correlation solve different problems, and a real SOC typically uses both together rather than picking one.

## 🔍 Splunk Cross-Check

Confirming the alert made it through the full pipeline (Suricata → eve.json → Splunk):

```
index=soc_lab sourcetype=suricata "1000001"
```

This returned exactly 1 event, matching the same alert, timestamp, and source/destination IPs seen in `eve.json`. One thing worth noting here: my first search attempt used `sid=1000001`, which returned nothing. The actual field Splunk extracts from the nested JSON is `alert.signature_id`, not a flat `sid` -- that field name only exists in Suricata's separate `fast.log` format, not `eve.json`. Searching on the raw signature ID string as a keyword was the quickest way to confirm ingestion without needing to get the exact nested field path right first.

## 🧠 What I Learned

The biggest lesson from this project wasn't the MTTD number itself, it was that my Project 02 rule looked syntactically perfect and loaded clean, but still failed its first real test. Writing a rule in the abstract and testing it against live, real-world tool behavior are two different skills, and only one of them tells you whether the rule actually works. I also learned that Hydra's connection-reuse behavior with SSH is itself a useful piece of threat intel -- it means a naive "count connections" detection rule can be trivially defeated just by lowering thread count, which is worth remembering if I ever tune a rule like this for a production environment instead of a lab. Finally, the field-naming mismatch between `eve.json`'s nested JSON and Suricata's flat `fast.log` format was a good reminder to always confirm actual field names in Splunk rather than assuming they match the log format documentation.

## 🎯 SOC Relevance

Sub-second detection matters enormously for time-sensitive attacks like brute force, where an attacker succeeding on attempt 26 out of 26 in under 3 seconds gives a human analyst working off a dashboard essentially zero window to react. Real-time IDS tools like Suricata are built to close that gap. But this project also demonstrates something just as important for a SOC analyst: the willingness to test a rule live, find out it doesn't work as expected, and understand why -- rather than assuming a clean config load and correct syntax mean the detection logic is sound.

## 🗺️ MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Brute Force | T1110 |
| Valid Accounts (target of brute force) | T1078 |

## ⏭️ Next Steps

Moving on to Project 04: Detecting Nmap Scans with Suricata, building on the NULL scan rule (SID 1000004) from Project 02 and testing it live against all six scan types the way I did in Wireshark Project 04.
