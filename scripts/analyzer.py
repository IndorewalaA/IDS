import json
import joblib
import pandas as pd
import numpy as np

with open('../models/training_metadata.json', 'r') as f:
    training_metadata = json.load(f)

REQUIRED_FEATURES = training_metadata['features_used']

le = joblib.load('../models/label_encoder.joblib')
rf = joblib.load('../models/random_forest.joblib')

def validate_json(data):
    if not isinstance(data, dict):
        return False, "Input is not a dictionary."
    missing_keys = [f for f in REQUIRED_FEATURES if f not in data]
    if missing_keys:
        return False, f"Missing keys: {missing_keys}."
    return True, "Data validated."

def predict_packet(packet: dict):
    df = pd.DataFrame([packet])
    # ensure columns are in the desired order
    df = df[REQUIRED_FEATURES]
    # replace infinities with 0
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    # predict label
    prediction = rf.predict(df)[0]
    label = le.inverse_transform([prediction])[0]
    return label


if __name__ == "__main__":
    test_packet = {
        "Destination Port": 80,
        "Flow Duration": 1500,
        "Total Fwd Packets": 2,
        "Total Backward Packets": 1,
        "Flow Bytes/s": 1250.0,
        "Flow Packets/s": 2.0,
        "Flow IAT Mean": 10.0,
        "Flow IAT Max": 50.0,
        "Packet Length Mean": 450.0,
        "Packet Length Std": 20.0,
        "Average Packet Size": 460.0,
        "SYN Flag Count": 1,
        "ACK Flag Count": 0,
        "PSH Flag Count": 0,
        "FIN Flag Count": 0
    }

    is_valid, msg = validate_json(test_packet)
    if is_valid:
        result = predict_packet(test_packet)
        print(result)