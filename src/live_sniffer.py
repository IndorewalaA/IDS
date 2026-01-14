import argparse
import boto3
import json
import os
import time
from scapy.all import sniff, IP, TCP, UDP, rdpcap, conf, get_if_list
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()

QUEUE_URL = 'https://sqs.us-east-2.amazonaws.com/007093308203/ids-queue'
sqs = boto3.client('sqs', region_name=os.getenv('AWS_REGION'))

'''5 tuple in networking:
source-ip
dest-ip
source-port
dest-port
protocol
'''
# to get IP info of each packet
def get_flow_key(packet):
    # only look at IP traffic
    if not packet.haslayer(IP):
        return None
    # extract IPs and protocol
    source_ip = packet[IP].src
    dest_ip = packet[IP].dst
    protocol = packet[IP].proto

    if TCP in packet:
        source_port = packet[TCP].sport
        dest_port = packet[TCP].dport
    elif UDP in packet:
        source_port = packet[UDP].sport
        dest_port = packet[UDP].dport
    else:
        source_port = 0
        dest_port = 0
    return (source_ip, dest_ip, source_port, dest_port, protocol)

# use IP info to classify flows
active_flows = defaultdict(lambda: {
    "start_time": 0,
    "last_seen": 0, 
    "packet_count": 0,
    "total_bytes": 0,
    "fwd_packets": 0,
    "bwd_packets": 0,
    "syn_count": 0,
    "ack_count": 0,
    "psh_count": 0,
    "fin_count": 0
})

def update_flows(key, packet):
    flow = active_flows[key]
    current_time = packet.time

    if flow["start_time"] == 0:
        flow["start_time"] == current_time

    flow["last_seen"] = current_time
    flow["packet_count"] += 1
    flow["total_bytes"] += len(packet)

    if packet[IP].src == key[0]:
        flow["fwd_packets"] += 1
    else:
        flow["bwd_packets"] += 1
    
    if TCP in packet:
        flags = packet[TCP].flags
        if 'S' in flags: flow["syn_count"] += 1
        if 'A' in flags: flow["ack_count"] += 1
        if 'P' in flags: flow["psh_count"] += 1
        if 'F' in flags: flow["fin_count"] += 1
    
    return flow

# If no packets for 1 second, end connection
def check_and_ship(key, flow):
    duration = flow["last_seen"] - flow["start_time"]
    if duration > 1.0 or flow["packet_count"] > 100:
        pkt_count = flow["packet_count"] if flow["packet_count"] > 0 else 1
        duration_sec = duration if duration > 0 else 1
        payload = {
            "Destination Port": key[3],
            "Flow Duration": int(duration * 1000), 
            "Total Fwd Packets": flow["fwd_packets"],
            "Total Backward Packets": flow["bwd_packets"],
            "Flow Bytes/s": float(flow["total_bytes"] / duration_sec),
            "Flow Packets/s": float(pkt_count / duration_sec),
            "Packet Length Mean": float(flow["total_bytes"] / pkt_count),
            "Average Packet Size": float(flow["total_bytes"] / pkt_count),
            "SYN Flag Count": flow["syn_count"],
            "ACK Flag Count": flow["ack_count"],
            "PSH Flag Count": flow["psh_count"],
            "FIN Flag Count": flow["fin_count"],
            "Flow IAT Mean": 0.0,
            "Flow IAT Max": 0.0,
            "Packet Length Std": 0.0
        }
        try:
            sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps(payload))
            print(f"Flow Sent: {key[0]} -> {key[1]}")
            del active_flows[key]
        except Exception as e:
            print(f"Error: {e}")

def process_packet(packet):
    key = get_flow_key(packet)
    if not key:
        return
    flow = update_flows(key, packet)
    check_and_ship(key, flow)

if __name__ == "__main__":
    print("Sniffer Started")
    print("Listening for traffic...")
    try:
        sniff(prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("Stopping...")
    except Exception as e:
        print(f"Error: {e}")