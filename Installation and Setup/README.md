# 01 - Installation & Setup

**Phase:** 1 -- Getting Started  
**Tools:** Suricata 8.0.5 · Splunk 10.4  
**Lab Environment:** Kali Linux · Windows 10 · VirtualBox NAT + Host-Only

---

## 🎯 What I Did

I installed Suricata 8.0.5 on Kali Linux, configured it to monitor two network interfaces simultaneously (eth0 for lab traffic and eth1 for internet-bound traffic), pulled 66,813 detection rules from the Emerging Threats Open and aleksibovellan/nmap rulesets, generated real attack traffic to populate alert data, and ingested the eve.json output into Splunk. The result is a working three-layer SOC detection environment where the same attacks are now visible at the packet level (Wireshark), the log level (Splunk), and the IDS signature level (Suricata) simultaneously.

---

## 🧠 Background -- The Three Detection Layers

With this project complete, my home SOC lab now has three complementary detection layers:

```
LAYER 1 -- Packet Level (Wireshark)
  Raw bytes, protocol dissection, manual analysis
  Best for: deep investigation, PCAP forensics

LAYER 2 -- Log Level (Splunk)
  OS events, auth logs, web logs, Zeek network logs
  Best for: correlation, alerting, dashboards, MTTD measurement

LAYER 3 -- IDS Signatures (Suricata)   <- THIS PROJECT
  Pattern matching against 66,813 known threat signatures
  Best for: real-time detection, known attack identification
```

Each layer catches things the others can miss. Suricata specifically catches attacks by matching traffic against known signatures -- it identified the Nmap scan type (SYN vs XMAS) and detected the RDP probe as Nmap-originated, which neither Wireshark nor Splunk would label explicitly without custom rules.

---

## ⚠️ Key Setup Decisions

### Dual Interface Monitoring

The most important configuration decision in this project was adding `eth1` as a second monitored interface alongside `eth0`. I discovered this was necessary when the `curl http://testmynids.org/uid/index.html` test did not fire any alerts -- because that traffic routes out through `eth1` (NAT/internet), not `eth0` (Host-Only lab network).

```yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
  - interface: eth1
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
```

After adding eth1, the testmynids.org test fired immediately:
```
GPL ATTACK_RESPONSE id check returned root {TCP} 108.157.78.25:80 -> 10.0.3.15:55042
```

This mirrors a real network sensor placement -- a single-interface IDS would miss anything not on that specific segment.

---

## 🔬 How I Set It Up

### Installation

```bash
sudo apt update
sudo apt install suricata -y
suricata --version
# Suricata 8.0.5
```

### Rule Sources Enabled

```bash
# Update source index
sudo suricata-update update-sources

# Enable Emerging Threats Open (free, 66,000+ rules)
sudo suricata-update enable-source et/open

# Enable dedicated Nmap detection ruleset
sudo suricata-update enable-source aleksibovellan/nmap

# Download and compile all rules
sudo suricata-update
```

Final rule count:
```bash
wc -l /var/lib/suricata/rules/suricata.rules
# 66,813 rules
```

### Config Validation

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
# Notice: suricata: Configuration provided was successfully loaded. Exiting.
```

### Starting Suricata

```bash
sudo systemctl restart suricata
sudo systemctl status suricata
```

### Splunk Integration

Fixed permissions so Splunk can read the log files:
```bash
sudo chmod 644 /var/log/suricata/eve.json
sudo chmod 644 /var/log/suricata/fast.log
```

Added data input in Splunk:
```
Settings -> Data Inputs -> Files & Directories -> New Local File & Directory
File:        /var/log/suricata/eve.json
Sourcetype:  suricata  (created as custom sourcetype)
Index:       soc_lab
```

Verified in Splunk -- 20 events returned immediately with structured JSON fields:
```splunk
index=soc_lab sourcetype=suricata
| head 20
```

---

## 📊 Attacks I Ran to Generate Alert Data

### 1. testmynids.org HTTP Test

```bash
curl http://testmynids.org/uid/index.html
```

**Alert fired:**
```
GPL ATTACK_RESPONSE id check returned root
{TCP} 108.157.78.25:80 -> 10.0.3.15:55042
```

Captured on eth1 -- confirmed dual-interface monitoring was working.

---

### 2. Nmap SYN Scan Against Windows 10 VM

```bash
sudo nmap -sS 192.168.56.101
```

**Alerts fired:**
```
POSSBL PORT SCAN (NMAP -sS) -- hundreds of alerts
ET SCAN RDP Connection Attempt from Nmap
SURICATA ICMPv4 unknown code
SURICATA Applayer Mismatch protocol both directions
```

The dedicated `aleksibovellan/nmap` ruleset identified the scan type explicitly by name rather than just flagging unusual traffic volume.

---

### 3. Nmap -A Full Scan (Version + OS + Scripts)

```bash
sudo nmap -sV -O -A 192.168.56.101
```

**Additional alerts fired:**
```
POSSBL PORT SCAN (NMAP -sX)
SURICATA SMB malformed request dialects (port 445)
ET SCAN RDP Connection Attempt from Nmap
```

The SMB malformed request alert fired when Nmap's script engine probed the Windows SMB service -- Suricata detected that the dialect negotiation was malformed compared to legitimate SMB traffic.

---

## 📊 Splunk Detection Searches

### All Suricata Alerts

```splunk
index=soc_lab sourcetype=suricata event_type=alert
| table _time alert.severity alert.signature alert.category src_ip dest_ip
| sort _time
```

### Alert Count by Signature

```splunk
index=soc_lab sourcetype=suricata event_type=alert
| stats count by alert.signature
| sort -count
```

### Alert Severity Breakdown

```splunk
index=soc_lab sourcetype=suricata event_type=alert
| stats count by alert.severity
| sort -count
```

### Alert Categories

```splunk
index=soc_lab sourcetype=suricata event_type=alert
| stats count by alert.category
| sort -count
```

### Top Source IPs Generating Alerts

```splunk
index=soc_lab sourcetype=suricata event_type=alert
| stats count by src_ip
| sort -count
```

---

## 💡 What I Learned

- **Single interface IDS misses traffic on other segments.** My first alert test failed because the traffic went out through eth1 while Suricata was only watching eth0. Adding eth1 as a second monitored interface fixed it immediately and mirrors how real network sensors need to be placed to cover all traffic paths, not just the internal network.

- **Dedicated scan detection rulesets are significantly more specific than generic rules.** The `aleksibovellan/nmap` ruleset fired `POSSBL PORT SCAN (NMAP -sS)` and `POSSBL PORT SCAN (NMAP -sX)` -- explicitly naming the tool and scan type. Without it I would have seen generic traffic anomaly alerts that required more analysis to attribute to Nmap specifically.

- **eve.json is richer than fast.log.** The fast.log format is human-readable and good for quick triage but eve.json contains structured JSON with dozens of fields per event -- source/destination IPs and ports, protocol, alert category and severity, rule SID, and for HTTP events the full URI and User-Agent. Splunk can search and aggregate all of those fields automatically once the JSON is ingested.

- **Suricata caught things Splunk and Wireshark did not label.** The `SURICATA SMB malformed request dialects` alert fired when Nmap probed port 445. In Wireshark I could see the SMB packets but identifying that the dialect negotiation was malformed required deep protocol knowledge. Suricata's protocol anomaly detection did it automatically.

- **66,813 rules cover attack surface I have not thought about yet.** Most rules will never fire in my lab -- they cover industrial protocols, specific CVEs, malware families, and cloud service abuse patterns. But every alert that does fire is backed by community threat intelligence from real incident data, making even noisy low-priority alerts more meaningful than generic anomaly detection would be.

- **The DHCP hostname leak alert was unexpected.** Suricata fired `ET INFO Possible Kali Linux hostname in DHCP Request Packet` every five minutes from the moment I started it. My Kali VM is broadcasting its hostname in DHCP requests, which is a real privacy issue in corporate environments -- an attacker on the same network could passively learn the machine hostname without actively scanning. This was a genuine finding from a tool that was just running in the background.

---

## 🔗 SOC Relevance

| Suricata Component | Real SOC Equivalent |
|---|---|
| eth0 + eth1 dual monitoring | IDS sensor on network tap covering multiple VLANs |
| 66,813 ET Open rules | Commercial threat intelligence feed subscription |
| eve.json forwarding to Splunk | Log shipper / syslog forwarding to SIEM |
| alert.signature in Splunk | IDS alert appearing in analyst console |
| aleksibovellan/nmap ruleset | Custom rule set added for specific threat actor TTPs |
| Protocol anomaly alerts (SMB, ICMP) | Behavioural detection complementing signature detection |

### MITRE ATT&CK -- Attacks Detected in This Project

| Technique | ID | Suricata Signature |
|---|---|---|
| Network Service Scanning | T1046 | POSSBL PORT SCAN (NMAP -sS/sX) |
| Active Scanning: Vulnerability Scanning | T1595.002 | ET SCAN RDP Connection Attempt from Nmap |
| Gather Victim Host Info | T1592 | SURICATA SMB malformed request dialects |

---

## 🛠️ Tools I Used

- **Suricata 8.0.5** -- IDS/IPS engine
- **Emerging Threats Open ruleset** -- 66,813 community detection rules
- **aleksibovellan/nmap ruleset** -- dedicated Nmap scan signatures
- **Splunk 10.4** -- SIEM integration via eve.json
- **Nmap** -- attack traffic generation
- **curl** -- HTTP test traffic
- **Kali Linux** -- lab environment
- **Windows 10** -- attack target VM

---

*Project 01 of 05 · [Back to Main Portfolio](../README.md)*
