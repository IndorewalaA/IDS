import os
import boto3
import json
from analyzer_logic import validate_json, predict_packet
from dotenv import load_dotenv

load_dotenv()

client = boto3.client(
    'sqs', 
    region_name=os.getenv('AWS_REGION', 'us-east-2'),
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
)

QUEUE_URL = 'https://sqs.us-east-2.amazonaws.com/007093308203/ids-queue'

def listen_to_queue():
    print(f"Listening to {QUEUE_URL}...")
    while True:
        response = client.receive_message(
            QueueUrl=QUEUE_URL,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=20
        )
        messages = response.get('Messages', [])
        for msg in messages:
            try:
                packet_data = json.loads(msg['Body'])
                is_valid, error_msg = validate_json(packet_data)
                if is_valid:
                    prediction = predict_packet(packet_data)
                    print(f"Prediction: {prediction}")
                else:
                    print(f"Bad packet: {error_msg} Skipping...")
                client.delete_message(
                    QueueUrl=QUEUE_URL,
                    ReceiptHandle=msg['ReceiptHandle']
                )
            except Exception as e:
                print(f"Error: {e}")
if __name__ == "__main__":
    print("Analyzer is Running...")
    listen_to_queue()
