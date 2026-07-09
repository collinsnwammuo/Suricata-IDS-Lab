# Suricata IDS Lab

**Tool:** Suricata 8.0.5  
**Integration:** Splunk 10.4 SIEM  
**Lab Environment:** Kali Linux · Windows 10 · VirtualBox NAT + Host-Only  
**Focus:** Intrusion detection · Rule management · Live attack detection · SIEM integration

---

## About This Repository

This repository documents my hands-on Suricata IDS lab -- the third detection layer in my home SOC environment alongside my [Wireshark packet analysis portfolio](https://github.com/collinsnwammuo/Wireshark-projects) and [Splunk SIEM portfolio](https://github.com/collinsnwammuo/SIEM-Splunk).

Suricata adds network-based intrusion detection to the lab. Where Wireshark shows packet-level evidence and Splunk correlates log data, Suricata watches live traffic and fires alerts the moment a known threat signature matches -- the same way a production IDS operates in a real SOC environment.

All Suricata alerts are forwarded to Splunk via `eve.json` ingestion, creating a unified detection platform where network alerts, host logs, and IDS signatures are searchable and correlatable in one index.

---

## Lab Architecture

```
Network Traffic (live on eth0 + eth1)
              |
              v
       Suricata 8.0.5
    (66,813 detection rules)
              |
              v
  /var/log/suricata/eve.json
  /var/log/suricata/fast.log
              |
              v
          Splunk 10.4
       index=soc_lab
       sourcetype=suricata
              |
              v
  Alerts, dashboards, correlation
  with linux_secure, zeek_conn,
  access_combined
```

### Network Interface Configuration

Suricata monitors **two interfaces simultaneously** -- a key setup decision made during this lab:

| Interface | Network | Purpose |
|---|---|---|
| `eth0` | 192.168.56.0/24 (Host-Only) | Lab traffic -- Nmap scans, SSH brute force, ARP spoofing |
| `eth1` | 10.0.3.0/24 (NAT) | Internet-bound traffic -- external threat detection |

Running a single-interface IDS on `eth0` only would miss any traffic going out through the NAT adapter. The dual-interface configuration mirrors how a real network sensor is placed to cover multiple network segments.

---

## Rulesets Installed

| Ruleset | Source | Rules | Description |
|---|---|---|---|
| Emerging Threats Open | `et/open` | 66,813 | Community threat intelligence -- malware, exploits, policy |
| Nmap Detection | `aleksibovellan/nmap` | Included | Explicit Nmap scan type signatures |

```bash
# How rulesets were installed
sudo suricata-update enable-source et/open
sudo suricata-update enable-source aleksibovellan/nmap
sudo suricata-update
```

---

## Alert Types Detected So Far

| Signature | Classification | Attack |
|---|---|---|
| `POSSBL PORT SCAN (NMAP -sS)` | Attempted Information Leak | Nmap SYN scan |
| `POSSBL PORT SCAN (NMAP -sX)` | Attempted Information Leak | Nmap XMAS scan |
| `ET SCAN RDP Connection Attempt from Nmap` | Detection of a Network Scan | Nmap RDP probe |
| `SURICATA SMB malformed request dialects` | Generic Protocol Command Decode | Nmap SMB probe |
| `GPL ATTACK_RESPONSE id check returned root` | Potentially Bad Traffic | testmynids.org test |
| `ET INFO Possible Kali Linux hostname in DHCP` | Potential Corporate Privacy Violation | DHCP hostname leak |
| `SURICATA ICMPv4 unknown code` | Generic Protocol Command Decode | ICMP anomaly |
| `SURICATA Applayer Mismatch protocol both directions` | Generic Protocol Command Decode | Protocol anomaly on port 135 |

---

## Project Index

| # | Project | Key Skills | Status |
|---|---------|------------|--------|
| 01 | [Installation & Setup](https://github.com/collinsnwammuo/Suricata-IDS-Lab/tree/main/Installation%20and%20Setup) | Install, dual-interface config, rule management, Splunk integration | ✅ Complete |
| 02 | [Writing Custom Rules](https://github.com/collinsnwammuo/Suricata-IDS-Lab/tree/main/Writing%20Custom%20Rules) | Rule anatomy, custom signatures, threshold tuning, testing | ✅ Complete |
| 03 | [Detecting SSH Brute Force](https://github.com/collinsnwammuo/Suricata-IDS-Lab/tree/main/Detecting%20SSH%20Brute%20Force) | Live Hydra attack, SSH signatures, MTTD measurement | ✅ Complete |
| 04 | [Detecting Nmap Scans](https://github.com/collinsnwammuo/Suricata-IDS-Lab/tree/main/Detecting%20Nmap%20Scans) | SYN/XMAS/NULL scan signatures, OS fingerprint detection | ✅ Complete |
| 05 | [Splunk Integration Dashboard](https://github.com/collinsnwammuo/Suricata-IDS-Lab/tree/main/Splunk%20Integration%20Dashboard) | Alert dashboard, severity classification, cross-source correlation | ✅ Complete |

---

## Suricata Rule Reference

### Rule Anatomy

```
action  protocol  src_ip  src_port  direction  dest_ip  dest_port  (options)

alert   tcp       any     any       ->         any      22         (
  msg:"SSH Brute Force Attempt";
  threshold:type threshold, track by_src, count 5, seconds 60;
  sid:9000001;
  rev:1;
)
```

| Field | Options | Description |
|---|---|---|
| `action` | alert, drop, reject, pass | What to do when rule matches |
| `protocol` | tcp, udp, icmp, http, dns, tls | Protocol to inspect |
| `direction` | `->` one-way, `<>` both ways | Traffic direction |
| `msg` | string | Human-readable alert name |
| `content` | string or hex | Match on payload bytes |
| `pcre` | regex | Regex pattern in payload |
| `threshold` | type, track, count, seconds | Rate-based triggering |
| `sid` | number | Unique rule ID (custom: 9000000+) |
| `rev` | number | Rule revision |

---

## Tools Used

- **Suricata 8.0.5** -- IDS/IPS engine
- **Emerging Threats Open ruleset** -- 66,813 community detection rules
- **aleksibovellan/nmap ruleset** -- dedicated Nmap scan detection
- **Splunk 10.4** -- SIEM integration via eve.json
- **Kali Linux** -- lab environment
- **Windows 10** -- attack target VM

---

*Companion repos: [Wireshark Portfolio](https://github.com/collinsnwammuo/Wireshark-projects) · [Splunk SIEM Portfolio](https://github.com/collinsnwammuo/SIEM-Splunk)*
