# threat-analysis-mitigation
A project documenting the process of analyzing network traffic logs, identifying threats, and detailing mitigation strategies using tools like Wireshark, Snort, and Suricata

# Threat Analysis and Mitigation
This repository contains a project documenting the process of analyzing a sample network traffic log, identifying threats, and detailing mitigation strategies.

## Tools Used
- **Wireshark**: For capturing and analyzing network packets.
- **Snort**: For intrusion detection and prevention.
- **Suricata**: For advanced network analysis and security monitoring.

## Objectives
- Understand network traffic patterns.
- Identify potential threats or anomalies.
- Implement strategies to mitigate identified threats.

## Contents
- `network-traffic-log.pcap`: Sample network traffic log for analysis.
- `threat-mitigation-report.md`: Detailed documentation of findings and strategies.
- Scripts and configurations used for analysis.

## How to Use
1. Clone this repository:
   ```bash
   git clone https://github.com/username/threat-analysis-mitigation.git

Open the .pcap file in Wireshark:

## Launch Wireshark.
- Click File > Open and select the network-traffic-log.pcap file from the cloned repository.
- Analyze the traffic log:

## Filter the Traffic: Use filters to focus on specific protocols or patterns:
- http to filter HTTP traffic.
- ip.addr == <IP_ADDRESS> to view traffic to/from a specific IP.
- tcp.port == 80 to focus on HTTP traffic on port 80.
- Inspect Suspicious Packets: Look for anomalies such as:
- Unusual IP addresses or domains.
- Excessive retransmissions or resets.
- Abnormal payload sizes.
- Follow a TCP Stream:
- Right-click on a suspicious packet and select "Follow TCP Stream" to see the conversation between hosts.
- Check for Malicious Indicators:
- Look for known malicious signatures or patterns.
- Analyze packet details for unexpected payloads.
- Document your findings:

## Note any suspicious activity, such as IPs or domains involved, packet contents, and potential threats.
Include these findings in the threat-mitigation-report.md.
Implement Mitigation Strategies:

## Based on the findings, recommend and document strategies for mitigation. Examples include:
Blocking malicious IPs.
Updating firewall rules.
Configuring IDS/IPS for detection and prevention.
