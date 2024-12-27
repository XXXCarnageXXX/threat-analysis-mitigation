import re

def ddos_detection(traffic):
    threshold = 50  # Set your threshold value here
    ddos_src_ips = [src for src, cnt in traffic if cnt > threshold]

    print(f"Potential DDoS detected: {ddos_src_ips}")

    # Add additional anomaly detection logic here as needed

# Run functions on the data parsed in traffic_analysis.py
# Ensure both modules import the required packages
from traffic_analysis import analyze_pcap, wireshark_analysis
traffic = analyze_pcap('wireshark_analysis.pcap').traffic_data
ddos_detection(traffic)
