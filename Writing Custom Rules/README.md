# 🛡️ Project 02: Writing Custom Suricata Rules

## 📋 Overview

After getting Suricata running with the default ET/open ruleset in Project 01, I wanted to understand rule writing from the ground up instead of just relying on rules someone else wrote. This project covers writing my own custom Suricata rules from scratch, validating their syntax, loading them alongside my existing ruleset, and confirming everything loads clean on a dual-interface setup.

My goal here wasn't to reinvent detection that ET/open already covers well. It was to understand the rule syntax deeply enough that I could write something targeted -- either filling a gap I noticed in Project 01, or tying detection back to traffic I'd already investigated in my Wireshark repo.

## 🖥️ Lab Setup

- Kali Linux VM, Suricata 8.0.5 (same environment as Project 01)
- Dual interface: eth0 (lab/Host-Only) + eth1 (NAT/internet), both configured under af-packet
- Custom rules file: `/var/lib/suricata/rules/local.rules`
- Registered in `/etc/suricata/suricata.yaml` under `rule-files`
- Alerts logged to `/var/log/suricata/eve.json`, ingested into Splunk under the `suricata` sourcetype and `soc_lab` index (same pipeline as Project 01)

## ✍️ Custom Rules Written

### 🔑 Rule 1: SSH Brute Force Detection (Threshold-Based)

```
alert tcp any any -> $HOME_NET 22 (msg:"CUSTOM SSH Brute Force Attempt - Multiple Failed Connections"; flow:to_server; flags:S; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-recon; sid:1000001; rev:1;)
```

I already knew from my Splunk Project 11 live brute force test that a real Hydra attack against my Windows 10 OpenSSH box ran 26 attempts in 28 seconds. I set my threshold to fire at 10 attempts within 60 seconds so it would trip well before an attacker got close to a working password, rather than waiting for a fixed count that might be too slow.

### 🕵️ Rule 2: NetSupport RAT C2 Pattern (tied to my Wireshark Project 06 investigation)

```
alert http $HOME_NET any -> 194.180.191.164 443 (msg:"CUSTOM Suspected NetSupport RAT C2 POST"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/fakeurl.htm"; classtype:trojan-activity; sid:1000002; rev:1;)
```

This one came directly out of the malware pcap I investigated in Wireshark Project 06 (the 2024-11-26 Nemotodes exercise). I already knew the C2 IP and the exact POST path from that investigation, so I wrote a rule that would catch that specific pattern. This ties my Wireshark and Suricata repos together -- a rule built from evidence I'd already confirmed was malicious, rather than a generic signature.

### 🌐 Rule 3: Suspicious Missing/Non-Browser User-Agent

```
alert http any any -> any any (msg:"CUSTOM Suspicious Empty or Missing User-Agent"; flow:to_server,established; http.method; content:"GET"; http.user_agent; content:!"Mozilla"; classtype:bad-unknown; sid:1000003; rev:1;)
```

A lot of malware and scripted tools don't bother spoofing a real browser User-Agent string. This rule is intentionally broad, since a lot of legitimate traffic (curl, wget, API calls) will also match it. Writing it this way was a deliberate choice -- it gave me a rule I could later tune down instead of a narrow one that only catches an exact scenario.

### 📡 Rule 4: Nmap NULL Scan Detection

```
alert tcp any any -> $HOME_NET any (msg:"CUSTOM Nmap NULL Scan Detected"; flags:0; classtype:attempted-recon; sid:1000004; rev:1;)
```

I already confirmed in Project 01 that ET/open catches SYN and XMAS scans, but I wanted a rule specifically for NULL scans (no TCP flags set at all) since I remembered from my Wireshark Project 04 work that Windows and Linux respond differently to this scan type.

## ✅ Validation Process

Before touching live traffic, I validated syntax on every rule:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

Output confirmed a clean load:

```
Info: detect: 2 rule files processed. 50912 rules successfully loaded, 0 rules failed, 0 rules skipped
Info: detect: 50917 signatures processed. 1271 are IP-only rules, 4505 are inspecting packet payload, 44895 inspect application layer, 110 are decoder event only
Notice: suricata: Configuration provided was successfully loaded. Exiting.
```

Both `suricata.rules` and `local.rules` processed with zero failures and zero skipped rules, confirming all four of my custom rules loaded correctly alongside the existing ET/open and Nmap rulesets.

## 🔌 Dual-Interface Configuration

Since Project 01 taught me that a single-interface setup can miss traffic depending on which adapter carries it, I made sure both `eth0` and `eth1` were explicitly configured under `af-packet` rather than relying on just the default interface. After restarting the service:

```bash
sudo systemctl restart suricata
sudo suricatasc -c iface-list
```

Both interfaces confirmed active and being monitored, so traffic across either the Host-Only lab network or the NAT/internet adapter gets inspected.

## 🧠 What I Learned

Writing a rule that's syntactically correct is the easy part. The harder part is thinking through what the rule will actually catch once it's live -- especially with Rule 3, where I deliberately kept the logic broad and knew going in that it would need tuning against real traffic before it'd be usable outside a lab. Tying Rule 2 back to a pcap I'd already investigated in my Wireshark repo also reinforced something I hadn't fully appreciated before: a detection rule is much easier to trust when you can point to the exact evidence that shaped it, rather than writing a signature in the abstract and hoping it generalizes. The dual-interface config was also a good reminder that a rule loading clean means nothing if the interface it needs to see traffic on isn't actually being monitored.

## 🎯 SOC Relevance

Understanding how to write custom Suricata rules matters because default rulesets, even a large one like ET/open, will never cover every environment-specific detection need. A SOC analyst who can only tune existing rules is limited; one who can write a new rule from scratch when a gap is identified -- whether from a live incident, a threat intel report, or a past investigation like my NetSupport RAT pcap -- is far more useful. This project also reinforced that a rule is only as good as the configuration supporting it. Writing a syntactically correct rule is easy. Making sure it's actually loaded, and that the interface it depends on is actually being monitored, is the part that matters in a real SOC.

## 🗺️ MITRE ATT&CK Mapping

| Rule | Technique | ID |
|---|---|---|
| 🔑 SSH Brute Force | Brute Force | T1110 |
| 🕵️ NetSupport RAT C2 | Application Layer Protocol / C2 | T1071 |
| 🌐 Suspicious User-Agent | Application Layer Protocol | T1071.001 |
| 📡 Nmap NULL Scan | Network Service Discovery | T1046 |

## ⏭️ Next Steps

Moving on to Project 03: live SSH brute force detection with Suricata, using the same live-fire methodology I used in Splunk Project 11 -- run a real attack, measure detection time, and see how Suricata's MTTD compares to what I measured in Splunk.
