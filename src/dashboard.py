import streamlit as st
import pandas as pd
import psycopg2
import os
import time
import plotly.express as px
from dotenv import load_dotenv

load_dotenv()

st.set_page_config(
    page_title='IDS Dashboard',
    page_icon="🛡️",
    layout="wide"
)

def get_connection():
    try:
        return psycopg2.connect(
            host=os.getenv('AWS_RDS_ENDPOINT'),
            database=os.getenv('AWS_RDS_NAME'),
            user=os.getenv('AWS_RDS_USER'),
            password=os.getenv('AWS_RDS_PASSWORD'),
            port=os.getenv('AWS_RDS_PORT')
        )
    except Exception as e:
        st.error(f"Connection failed: {e}")
        return None

def fetch_data():
    connection = get_connection()
    if connection:
        query = "SELECT * FROM attack_logs ORDER BY event_time DESC LIMIT 1000;"
        df = pd.read_sql(query, connection)
        connection.close()
        return df
    return pd.DataFrame()

st.title("Real-Time Intrusion Detection System")
if st.button("Refresh Data"):
    st.rerun()
df = fetch_data()

if not df.empty:
    total_attacks = len(df)
    unique_types = df['prediction'].nunique()
    most_recent = df['event_time'].max().strftime('%H:%M:%S')

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Threats Detected", total_attacks)
    col2.metric("Attack Types", unique_types)
    col3.metric("Last Detection", most_recent)
    st.markdown("---")
    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("Attack Distribution")
        fig_pie = px.pie(df, names='prediction', title='Threat Breakdown', hole=0.4)
        st.plotly_chart(fig_pie, width='stretch')
    with col_right:
        st.subheader("Attack Timeline")
        df['event_time'] = pd.to_datetime(df['event_time'])
        timeline = df.set_index('event_time').resample('1T').size().reset_index(name='count')
        fig_line = px.line(timeline, x='event_time', y='count', title='Attacks per Minute')
        st.plotly_chart(fig_line, use_container_width=True)
    st.subheader("📝 Recent Logs")
    st.dataframe(df[['event_time', 'destination_port', 'prediction', 'flow_duration']].head(10))
else:
    st.info("No attacks detected yet. System is secure (or waiting for traffic).")