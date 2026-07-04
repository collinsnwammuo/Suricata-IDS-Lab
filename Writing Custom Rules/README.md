# Project 02: Writing Custom Suricata Rules

## Overview

After getting Suricata running with the default ET/open ruleset in Project 01, I wanted to understand rule writing from the ground up instead of just relying on rules someone else wrote. This project covers writing my own custom Suricata rules from scratch, validating their syntax, loading them alongside my existing ruleset, and testing each one against real traffic I generated myself.

My goal here wasn't to reinvent detection that ET/open already covers well. It was to understand the rule syntax deeply enough that I could write something targeted -- either filling a gap I noticed in Project 01, or tying detection back to traffic I'd already investigated in my Wireshark repo.

## Lab Setup

- Kali Linux VM, Suricata 8.0.5 (same environment as Project 01)
- Dual interface: eth0 (lab/Host-Only) + eth1 (NAT/internet)
- Custom rules file: `/var/lib/suricata/rules/local.rules`
- Registered in `/etc/suricata/suricata.yaml` under `rule-files`
- Alerts logged to `/var/log/suricata/eve.json`, ingested into Splunk under the `suricata` sourcetype and `soc_lab` index (same pipeline as Project 01)

## Custom Rules Written

### Rule 1: SSH Brute Force Detection (Threshold-Based)

```
alert tcp any any -> $HOME_NET 22 (msg:"CUSTOM SSH Brute Force Attempt - Multiple Failed Connections"; flow:to_server; flags:S; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-recon; sid:1000001; rev:1;)
```

I already knew from my Splunk Project 11 live brute force test that a real Hydra attack against my Windows 10 OpenSSH box ran 26 attempts in 28 seconds. I set my threshold to fire at 10 attempts within 60 seconds so it would trip well before an attacker got close to a working password, rather than waiting for a fixed count that might be too slow.

### Rule 2: NetSupport RAT C2 Pattern (tied to my Wireshark Project 06 investigation)

```
alert http $HOME_NET any -> 194.180.191.164 443 (msg:"CUSTOM Suspected NetSupport RAT C2 POST"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/fakeurl.htm"; classtype:trojan-activity; sid:1000002; rev:1;)
```

This one came directly out of the malware pcap I investigated in Wireshark Project 06 (the 2024-11-26 Nemotodes exercise). I already knew the C2 IP and the exact POST path from that investigation, so I wrote a rule that would catch that specific pattern. Replaying that pcap through Suricata let me prove the rule actually fires on traffic I'd already confirmed was malicious, instead of just trusting that the syntax was correct.

### Rule 3: Suspicious Missing/Non-Browser User-Agent

```
alert http any any -> any any (msg:"CUSTOM Suspicious Empty or Missing User-Agent"; flow:to_server,established; http.method; content:"GET"; http.user_agent; content:!"Mozilla"; classtype:bad-unknown; sid:1000003; rev:1;)
```

A lot of malware and scripted tools don't bother spoofing a real browser User-Agent string. This rule is intentionally broad and noisy -- I wanted to see how much legitimate traffic (curl, wget, API calls) also gets flagged, so I could get a feel for tuning a rule like this down in a real environment instead of just writing it and assuming it works.

### Rule 4: Nmap NULL Scan Detection

```
alert tcp any any -> $HOME_NET any (msg:"CUSTOM Nmap NULL Scan Detected"; flags:0; classtype:attempted-recon; sid:1000004; rev:1;)
```

I already confirmed in Project 01 that ET/open catches SYN and XMAS scans, but I wanted a rule specifically for NULL scans (no TCP flags set at all) since I remembered from my Wireshark Project 04 work that Windows and Linux respond differently to this scan type.

## Validation Process

Before touching live traffic, I validated syntax on every rule:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

[Fill in: paste your actual output confirming "Configuration provided was successfully loaded" and any errors you had to fix along the way]

## Testing Each Rule

**Rule 1 (SSH brute force):** Ran Hydra against my Windows 10 OpenSSH VM the same way I did in Splunk Project 11, then watched `eve.json` for the alert.

**Rule 2 (NetSupport RAT C2):** Replayed the Nemotodes pcap using `tcpreplay` on the lab interface.

**Rule 3 (User-Agent):** Ran `curl -A "" http://<test-target>` to generate a request with no User-Agent header.

**Rule 4 (NULL scan):** Ran `nmap -sN <target>` from Kali against the Windows 10 VM.

[Fill in: your actual eve.json alert output for each rule, timestamps, and whether each one fired as expected on the first try or needed tuning]

## What I Learned

[Fill in once you've run the tests -- some things worth covering based on what usually comes up at this stage:]
- Whether the threshold values you picked were too sensitive or not sensitive enough once you saw real alert volume
- Any false positives you hit, especially on Rule 3, and how you'd tune it in a production environment
- Anything about SID numbering or rule ordering that tripped you up
- Differences between writing a rule "cold" versus writing one where you already had a known-malicious pcap to validate against (Rule 2 vs the others)

## SOC Relevance

Understanding how to write custom Suricata rules matters because default rulesets, even a large one like ET/open, will never cover every environment-specific detection need. A SOC analyst who can only tune existing rules is limited; one who can write a new rule from scratch when a gap is identified -- whether from a live incident, a threat intel report, or a past investigation like my NetSupport RAT pcap -- is far more useful. This project also reinforced that a rule is only as good as the testing behind it. Writing syntactically correct Suricata rules is easy. Proving they actually fire on the traffic they're meant to catch, and understanding their false positive behavior, is the part that actually matters in a real SOC.

## MITRE ATT&CK Mapping

| Rule | Technique | ID |
|---|---|---|
| SSH Brute Force | Brute Force | T1110 |
| NetSupport RAT C2 | Application Layer Protocol / C2 | T1071 |
| Suspicious User-Agent | Application Layer Protocol | T1071.001 |
| Nmap NULL Scan | Network Service Discovery | T1046 |

## Next Steps

Moving on to Project 03: live SSH brute force detection with Suricata, using the same live-fire methodology I used in Splunk Project 11 -- run a real attack, measure detection time, and see how Suricata's MTTD compares to what I measured in Splunk.
