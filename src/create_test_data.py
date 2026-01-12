import pandas as pd
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_DIR = os.path.join(BASE_DIR, '..', 'datasets')

INPUT_FILES = [
    os.path.join(DATASET_DIR, 'Monday-WorkingHours.pcap_ISCX.csv'),
    os.path.join(DATASET_DIR, 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'),
    os.path.join(DATASET_DIR, 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'),
    os.path.join(DATASET_DIR, 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')
]

def create_test_csv(output_path='test_data/test_data.csv'):
    all_chunks = []
    for file in INPUT_FILES:
        if os.path.exists(file):
            print(f"Processing: {os.path.basename(file)}")
            df = pd.read_csv(file)
            df.columns = df.columns.str.strip()
            df['Label'] = df['Label'].replace({
                'Web Attack � Brute Force': 'Web Attack',
                'Web Attack � Sql Injection': 'Web Attack',
                'Web Attack � XSS': 'Web Attack'
            })
            if 'Monday' in file:
                chunk = df[df['Label'] == 'BENIGN'].sample(n=100, random_state=42)
            else:
                attacks_only = df[df['Label'] != 'BENIGN']
                n_samples = min(len(attacks_only), 100)
                chunk = attacks_only.sample(n=n_samples, random_state=42)
            all_chunks.append(chunk)
    if all_chunks:
        test_df = pd.concat(all_chunks).sample(frac=1, random_state=42).reset_index(drop=True)
        output_dir = os.path.join(BASE_DIR, '..', 'test_data')
        os.makedirs(output_dir, exist_ok=True)
        final_path = os.path.join(output_dir, 'test_data.csv')
        test_df.to_csv(final_path, index=False)
        print("File Creation Successful!")
        print(f"Size: {test_df['Label'].value_counts()}")
    else:
        print("No data found.")
    
if __name__ == "__main__":
    create_test_csv()