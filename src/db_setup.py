import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

def setup_database():
    try:
        connection = psycopg2.connect(
            host=os.getenv('AWS_RDS_ENDPOINT'),
            database=os.getenv('AWS_RDS_NAME'),
            user=os.getenv('AWS_RDS_USER'),
            password=os.getenv('AWS_RDS_PASSWORD'),
            port=os.getenv('AWS_RDS_PORT')
        )
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_logs (
                id SERIAL PRIMARY KEY,
                event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                destination_port INTEGER,
                prediction  VARCHAR(50),
                flow_duration BIGINT
            );
        """)
        connection.commit()
        print("attack_logs table created!")
        cursor.close()
        connection.close()
    except Exception as e:
        print(f"Database setup failed. {e}")

if __name__ == "__main__":
    setup_database()