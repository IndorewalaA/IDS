import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

def view_all_data():
    try:
        conn = psycopg2.connect(
            host=os.getenv('AWS_RDS_ENDPOINT'),
            database=os.getenv('AWS_RDS_NAME'),
            user=os.getenv('AWS_RDS_USER'),
            password=os.getenv('AWS_RDS_PASSWORD'),
            port=os.getenv('AWS_RDS_PORT')
        )
        cur = conn.cursor()
        cur.execute("SELECT * FROM attack_logs ORDER BY event_time DESC;")
        colnames = [desc[0] for desc in cur.description]
        print(" | ".join(f"{name:<15}" for name in colnames))
        print("-" * (len(colnames) * 18))
        rows = cur.fetchall()
        for row in rows:
            print(" | ".join(f"{str(val):<15}" for val in row))
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Failed to fetch data: {e}")

if __name__ == "__main__":
    view_all_data()