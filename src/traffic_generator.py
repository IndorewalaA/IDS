# selects a random packet from db to send random packets from data to sqs server.
import os
import boto3
import json
import time
import concurrent.futures
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

QUEUE_URL = 'https://sqs.us-east-2.amazonaws.com/007093308203/ids-queue'
client = boto3.client(
    'sqs',
    region_name=os.getenv('AWS_REGION', 'us-east-2'),
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
)

def send_packet(packet_dict=dict):
    try:
        client.send_message(
            QueueUrl=QUEUE_URL,
            MessageBody=json.dumps(packet_dict)
        )
        return True
    except Exception as e:
        print(f"Packet not sent: {e}")
        return False

def run_generator(file_path, num_packets, max_workers):
    if not os.path.exists(file_path):
        print(f"Error: {file_path} doesn't exist!")
        return
    print("Loading data...")
    df = pd.read_csv(file_path)
    packets = df.sample(n=num_packets, replace=True).to_dict(orient='records')
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(send_packet, packets))
    success_count = sum(results)
    print(f"{success_count} packets successfully sent! {num_packets} total.")

if __name__ == '__main__':
    DATA_PATH = os.path.join("test_data", "test_data.csv")
    print(DATA_PATH)
    run_generator(DATA_PATH, 100, 10)