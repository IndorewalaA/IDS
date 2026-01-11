import os
import boto3
import json
import psycopg2
from analyzer_logic import validate_json, predict_packet
from dotenv import load_dotenv

load_dotenv()

def log_to_db(prediction: str, packet_data):
    try:
        connection = psycopg2.connect(
            host=os.getenv('AWS_RDS_ENDPOINT'),
            database=os.getenv('AWS_RDS_NAME'),
            user=os.getenv('AWS_RDS_USER'),
            password=os.getenv('AWS_RDS_PASSWORD'),
            port=os.getenv('AWS_RDS_PORT')
        )
        cursor = connection.cursor()
        query = """
            INSERT INTO attack_logs (destination_port, prediction, flow_duration)
            VALUES (%s, %s, %s)
        """
        data = (
            packet_data.get('Destination Port'),
            prediction,
            packet_data.get('Flow Duration')
        )
        cursor.execute(query, data)
        connection.commit()
        print("Anomaly logged.")
        cursor.close()
        connection.close()
    except Exception as e:
        print(f"Log failed!")

def listen_to_queue():
    client = boto3.client(
        'sqs', 
        region_name=os.getenv('AWS_REGION', 'us-east-2'),
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
    )
    QUEUE_URL = 'https://sqs.us-east-2.amazonaws.com/007093308203/ids-queue'

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
                    if prediction != "BENIGN":
                        log_to_db(prediction, packet_data)
                else:
                    print(f"Bad packet: {error_msg} Skipping...")
                client.delete_message(QueueUrl=QUEUE_URL, ReceiptHandle=msg['ReceiptHandle'])
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    print("Analyzer is Running...")
    listen_to_queue()
