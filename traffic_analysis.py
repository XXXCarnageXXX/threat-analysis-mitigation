import pyshark

def analyze_traffic(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    packet_count = 0
    http_requests = 0
    suspicious_traffic = 0

    for packet in capture:
        packet_count += 1
        # Analyze HTTP packets for suspicious behavior
        if 'HTTP' in packet:
            http_requests += 1
            if 'GET' in packet.http.request_method or 'POST' in packet.http.request_method:
                print(f"HTTP Request: {packet.http.request_method} {packet.http.host}{packet.http.uri}")
        
        # Look for suspicious traffic patterns (e.g., a high number of requests from the same IP)
        if 'IP' in packet:
            src_ip = packet.ip.src
            print(f"Packet from {src_ip}")
            # Check for DDoS or scanning behavior here
        
        # Define custom rules for identifying threats like DoS or scanning attempts
        
    print(f"Total Packets: {packet_count}")
    print(f"Total HTTP Requests: {http_requests}")
    # Report suspicious traffic if any
    if suspicious_traffic > 0:
        print("Suspicious traffic detected.")
    
if __name__ == "__main__":
    analyze_traffic("wireshark_analysis.pcap")  # replace with your actual file path
