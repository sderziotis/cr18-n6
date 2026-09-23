# CR-18 / Module 6 — Traffic Analysis

A KYPO cyber range training module built around offline packet-capture analysis, delivered as two linked labs (N6a and N6b) set at a fictional company, Orion Retail Ltd.

## Overview

Unlike the earlier modules in this course, Module 6 is not a live exploitation exercise — trainees are handed forensic evidence (packet captures, and in N6b an IDS alert log) from incidents that already happened, and must reconstruct what occurred purely through traffic analysis. There is no live target network to attack; both labs are explicitly framed as offline incident reviews.

- **N6a — Traffic Analysis CTF1** investigates a suspected unauthorized access to an internal web admin panel using a single packet capture. Trainees recover credentials exposed by insecure protocols, assess an obsolete TLS configuration from its handshake, and reconstruct a file that was exfiltrated over the network.
- **N6b — Traffic Analysis CTF2** picks up after the first incident, once a signature-based IDS has been deployed. Trainees analyze a second capture alongside the IDS's alert log to work out how an intrusion evaded detection — separating a decoy scan from the real attacker by MAC address, then locating and reassembling a fragmented, obfuscated payload the IDS never flagged. It closes with a short assessment on the key facts of the investigation.

Both labs run on the same sandbox and are intended to be completed in order, with N6b assuming familiarity with the tooling and techniques introduced in N6a.

## Prerequisites

**N6a:**
- Comfort using a Linux shell
- Working knowledge of TCP/IP: layers, ports, and common application protocols
- Familiarity with Wireshark display filters (not taught from scratch)

**N6b:**
- Completion of N6a, or equivalent Wireshark/tshark experience
- Comfort with display filters, following TCP streams, and IP fragment reassembly
- Awareness that an IDS alert is a signature match on a packet, not a conclusion

## Learning Outcomes

**N6a:**
- Perform structured packet analysis using Wireshark and tshark
- Identify and extract cleartext credentials transmitted over insecure protocols
- Detect weak or misconfigured encryption by inspecting a TLS handshake
- Reconstruct files transferred over the network from a packet capture
- Correlate observed network data to the underlying security misconfigurations

**N6b:**
- Analyze fragmented and obfuscated network traffic to identify a real attack
- Correlate a packet capture with IDS alerts to separate genuine activity from decoys
- Reassemble and extract a payload from fragmented traffic
- Explain how fragmentation and decoys evade signature-based IDS detection

## Scenario Structure

**N6a — Traffic Analysis CTF1**

| # | Title | Type |
|---|-------|------|
| 0 | Introduction | Info |
| 1 | Get Access | Access (console login) |
| 2 | Credentials In The Clear | Training |
| 3 | Encryption That Is Not Protecting Anything | Training |
| 4 | Rebuild What Left The Building | Training |
| 5 | Lab Completed | Info |

Estimated duration: ~45 minutes.

**N6b — Traffic Analysis CTF2**

| # | Title | Type |
|---|-------|------|
| 0 | Introduction | Info |
| 1 | Get Access | Access (console login) |
| 2 | What The IDS Missed | Training |
| 3 | Incident Questions | Assessment |
| 4 | Lab Completed | Info |

Estimated duration: ~42 minutes.

## Topology

Both labs share a single, minimal sandbox:

- **Analysis workstation** — the trainee's only machine, pre-equipped with packet analysis tooling. Trainees work entirely against provided evidence files rather than a live network.
- **Router** — provides the sandbox's network connectivity.

The network the evidence was captured from no longer exists in the sandbox — there is nothing live to scan or connect to. Both labs are self-contained forensic exercises rather than network attack exercises.

## Skills Practiced

- Structured packet capture analysis with Wireshark and tshark
- Building and applying display filters to isolate relevant traffic
- Recognizing cleartext and weakly-protected credential exposure
- Evaluating a TLS handshake for weak protocol/cipher configuration and certificate issues
- Extracting and reconstructing transferred files from captured traffic
- Distinguishing genuine attack traffic from decoy/spoofed activity using link-layer evidence
- Understanding and reassembling fragmented traffic to recover an evasive payload
- Decoding an obfuscated payload recovered from network traffic

## MITRE ATT&CK Coverage

Techniques referenced across the two labs include:

- Network Sniffing (T1040)
- Adversary-in-the-Middle (T1557)
- Application Layer Protocol (T1071)
- Exfiltration Over C2 Channel (T1041)
- Obfuscated Files or Information (T1027)
- Active Scanning (T1595)
- Data Obfuscation (T1030)

## Notes

This repository contains the scenario definition (topology and training content) for deployment on a KYPO-based cyber range. Solutions, hints, and flag/answer values are intentionally excluded from this README.
