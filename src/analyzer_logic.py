import os
import joblib
import pandas as pd
import numpy as np
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "models"))

metadata_path = os.path.join(MODEL_DIR, 'training_metadata.json')
with open(metadata_path, 'r') as f:
    training_metadata = json.load(f)

REQUIRED_FEATURES = training_metadata['features_used']

le = joblib.load(os.path.join(MODEL_DIR, 'label_encoder.joblib'))
rf = joblib.load(os.path.join(MODEL_DIR, 'random_forest.joblib'))

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