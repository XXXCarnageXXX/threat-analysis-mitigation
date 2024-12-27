import pyshark

def detect_ddos(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    ip_count = {}
    threshold = 100  # Define a threshold for detecting too many requests from one IP
    
    for packet in capture:
        if 'IP' in packet:
            src_ip = packet.ip.src
            if src_ip in ip_count:
                ip_count[src_ip] += 1
            else:
                ip_count[src_ip] = 1
    
    # Check if any IP exceeds the threshold (possible DDoS attempt)
    for ip, count in ip_count.items():
        if count > threshold:
            print(f"Potential DDoS detected: IP {ip} sent {count} packets.")
    
if __name__ == "__main__":
    detect_ddos("wireshark_analysis.pcap")  # replace with your actual file path
