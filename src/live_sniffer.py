import argparse
import boto3
import json
import os
import time
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()

QUEUE_URL = 'https://sqs.us-east-2.amazonaws.com/007093308203/ids-queue'
sqs = boto3.client('sqs', region_name=os.getenv('AWS_REGION'))
ip_history = defaultdict(list)

def get_host_count(source_ip):
    current_time = time.time()
    ip_history[source_ip].append(current_time)
    ip_history[source_ip] = [t for t in ip_history[source_ip] if current_time - t <= 2.0]
    return len(ip_history[source_ip])
LOOPBACK_NAME = r"\Device\NPF_Loopback" 

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

def get_flow_key(packet):
    if not packet.haslayer(IP):
        return None
    
    # NOISE FILTER: Only look at localhost for testing
    if packet[IP].dst != "127.0.0.1" and packet[IP].src != "127.0.0.1":
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    
    src_port = 0
    dst_port = 0

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    if src_ip < dst_ip:
        return (src_ip, dst_ip, src_port, dst_port, proto)
    elif src_ip > dst_ip:
        return (dst_ip, src_ip, dst_port, src_port, proto)
    else:
        if src_port <= dst_port:
            return (src_ip, dst_ip, src_port, dst_port, proto)
        else:
            return (src_ip, dst_ip, dst_port, src_port, proto)

def update_flows(key, packet):
    flow = active_flows[key]
    current_time = packet.time

    if flow["start_time"] == 0:
        flow["start_time"] = current_time

    flow["last_seen"] = current_time
    flow["packet_count"] += 1
    flow["total_bytes"] += len(packet)

    is_forward = False
    if packet[IP].src == key[0]:
        if key[0] == key[1]: 
            if (TCP in packet and packet[TCP].sport == key[2]) or \
               (UDP in packet and packet[UDP].sport == key[2]):
                is_forward = True
        else:
            is_forward = True

    if is_forward:
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

def check_and_ship(key, flow):
    duration = flow["last_seen"] - flow["start_time"]
    
    if duration > 1.0 or flow["packet_count"] > 100:
        if duration == 0: duration = 0.000001
        
        host_count = get_host_count(key[0]) 

        payload = {
            "Destination Port": int(key[3]),
            "Flow Duration": int(duration * 1000000), 
            "Total Fwd Packets": flow["fwd_packets"],
            "Total Backward Packets": flow["bwd_packets"],
            "Flow Bytes/s": float(flow["total_bytes"] / duration),
            "Flow Packets/s": float(flow["packet_count"] / duration),
            "Flow IAT Mean": 0.0,
            "Flow IAT Max": 0.0,
            "Packet Length Mean": float(flow["total_bytes"] / flow["packet_count"]),
            "Packet Length Std": 0.0,
            "Average Packet Size": float(flow["total_bytes"] / flow["packet_count"]),
            "SYN Flag Count": flow["syn_count"],
            "ACK Flag Count": flow["ack_count"],
            "PSH Flag Count": flow["psh_count"],
            "FIN Flag Count": flow["fin_count"],
            "Host_Count": host_count # <--- NEW FEATURE
        }
        
        try:
            sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps(payload))
            print(f"Flow Sent: {key[0]} -> {key[1]} | Host Count: {host_count}")
            del active_flows[key]
        except Exception as e:
            print(f"SQS Error: {e}")

def process_packet(packet):
    key = get_flow_key(packet)
    if not key:
        return
    flow = update_flows(key, packet)
    check_and_ship(key, flow)

if __name__ == "__main__":
    print(f"Sniffer Started on {LOOPBACK_NAME}")
    try:
        sniff(iface=LOOPBACK_NAME, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("Stopping...")
    except Exception as e:
        print(f"Error: {e}")