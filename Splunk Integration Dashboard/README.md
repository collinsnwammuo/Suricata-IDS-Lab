# 📊 Project 05: Suricata Splunk Integration Dashboard

## 📋 Overview

This project pulls everything from Projects 01-04 into a single Splunk dashboard: scan detection results, alert volume over time, top signatures, and the SSH brute force detection from Project 03. The goal was to stop treating each project's findings as separate one-off tests and instead build a unified view a SOC analyst could actually use to monitor the lab in real time.

The most important design decision here was turning the Project 04 scan coverage findings (which scans get detected and which don't) into a permanent panel on the dashboard itself, rather than leaving that information buried in a README. A real detection stack should make its own blind spots visible, not just document them after the fact.

## 🖥️ Lab Setup

- Splunk 10.4.0 on Kali, index `soc_lab`, sourcetype `suricata`
- Dashboard built in Splunk Classic Dashboard Studio
- Data pulled from all prior Suricata testing: Projects 01-04 (custom rules, live SSH brute force, and the six Nmap scan types)

## 🧩 Dashboard Panels

### 📈 Alert Volume Over Time
```
index=soc_lab sourcetype=suricata event_type=alert
| timechart span=1m count by alert.signature
```
This panel makes the scale of the NULL scan detection immediately obvious: my custom rule (SID 1000004) generated a spike of roughly 3,000 individual alert events during the ~22-second scan window, dwarfing every other signature on the timeline. The SYN, XMAS, and ACK scan alerts show up as much smaller, shorter bursts by comparison. Seeing this visually was actually useful beyond just confirming detection: it highlighted just how noisy a threshold-less custom rule can be in practice, since SID 1000004 fires on every single packet matching the NULL flag pattern rather than aggregating with a threshold like my SSH brute force rule does.

### 🏆 Top Alert Signatures
```
index=soc_lab sourcetype=suricata event_type=alert
| top limit=10 alert.signature
```
Confirms the same story as a ranked bar chart: CUSTOM Nmap NULL Scan Detected leads by a wide margin, followed by the ET/open XMAS, SYN, and ACK scan signatures, with the DHCP hostname alert and SSH brute force alert appearing lower down since those only fire once or a handful of times rather than per-packet.

### 🗂️ Scan Detection Coverage Table
```
| makeresults
| eval scan_type="SYN", detected="Yes", signature="3400001/3400002"
| append [| makeresults | eval scan_type="NULL", detected="Yes (custom rule)", signature="1000004"]
| append [| makeresults | eval scan_type="FIN", detected="No", signature="none"]
| append [| makeresults | eval scan_type="XMAS", detected="Yes", signature="3400005"]
| append [| makeresults | eval scan_type="ACK", detected="Yes", signature="3400004"]
| append [| makeresults | eval scan_type="Connect", detected="No", signature="none"]
| table scan_type, detected, signature
```
This is the panel I care about most. It puts the Project 04 findings, including the FIN scan and TCP connect scan detection gaps, directly on the dashboard instead of leaving them in a README someone might not read. Anyone looking at this dashboard can see at a glance that 4 of 6 scan types are covered, which two aren't, and why that matters, without digging through prior project documentation.

### 🔐 SSH Brute Force Detection
```
index=soc_lab sourcetype=suricata "1000001"
| table _time, src_ip, dest_ip, dest_port, alert.signature
```
Pulls the exact Project 03 alert: source 192.168.56.102, destination 192.168.56.101 on port 22, timestamped 2026-07-04 14:24:12.875, matching the sub-second MTTD result documented earlier.

## 🧠 What I Learned

Building this dashboard surfaced something the individual project READMEs didn't make obvious: the sheer alert volume difference between a per-packet rule (my NULL scan rule) and a thresholded rule (my SSH brute force rule). Seeing roughly 3,000 alerts from a single 22-second NULL scan next to a single brute force alert really highlighted why threshold tuning matters, not just for accuracy but for keeping a SOC analyst's alert queue usable. A rule that fires on every matching packet rather than aggregating creates a very different operational experience than one that fires once per meaningful event. I also learned that a coverage table like the one I built here is genuinely more valuable as a live dashboard panel than as static documentation, since it's the kind of thing that should get updated and referenced continuously as new rules get added or gaps get closed.

## 🎯 SOC Relevance

A SOC analyst's dashboard is only as good as its honesty about what it does and doesn't catch. Building the scan coverage table directly into this dashboard, rather than treating detection gaps as something to note separately, reflects how real detection engineering teams track and communicate ruleset coverage over time. The alert volume panel also demonstrates a practical tuning consideration that matters a lot in production: an untuned, per-packet rule can flood a queue and bury genuinely urgent alerts under noise, which is exactly the kind of problem a working SOC has to manage continuously, not just something to notice once in testing.

## 🗺️ MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Network Service Discovery | T1046 |
| Brute Force | T1110 |
| Application Layer Protocol / C2 | T1071 |


