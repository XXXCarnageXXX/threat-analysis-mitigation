import pynetwork, re
import pandas as pd

def analyze_pcap(file):
    # parse PCAP file and convert data to DataFrame
    network = pynetwork.open_packet_file(file)
    df = pynetwork.io.to_dataframe(network)

    # filter HTTP packets and report HTTP request types (GET, POST)
    http_df = df[df["prot"] == "TCP"].query('data.find(b"Host") > -1')
    http_req_type_counts = http_df.groupby(lambda x: 'GET' if x["data"].find(b" GET") > 0 else 'POST').count()

    print("HTTP Request types:\n", http_req_type_counts)

    # detect high traffic from the same source IP
    same_src_ip_traffic = http_df[http_df["srcip"] == http_df["srcip"].iloc[0]].groupby(lambda x: x["dstip"]).size().values.tolist()

    for idx, count in enumerate(same_src_ip_traffic):
        if count > threshold:  # Set your threshold value here
            print(f"Suspicious traffic detected: {idx}:{count} from {http_df['srcip'][0]}")
