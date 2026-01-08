import pytest
from src.analyzer import predict_packet, validate_json

@pytest.mark.parametrize("packet, expected", [
    ({
        'Destination Port': 443, 'Flow Duration': 92752184, 'Total Fwd Packets': 19, 
        'Total Backward Packets': 16, 'Flow Bytes/s': 51.3518905388, 'Flow Packets/s': 0.3773496051, 
        'Flow IAT Mean': 2728005.41176471, 'Flow IAT Max': 10170359, 'Packet Length Mean': 132.3055555556, 
        'Packet Length Std': 426.1720524084, 'Average Packet Size': 136.0857142857, 'SYN Flag Count': 0, 
        'ACK Flag Count': 0, 'PSH Flag Count': 1, 'FIN Flag Count': 0
    }, "BENIGN"),
    ({
        'Destination Port': 80, 'Flow Duration': 10037427, 'Total Fwd Packets': 5, 
        'Total Backward Packets': 0, 'Flow Bytes/s': 2.988813767, 'Flow Packets/s': 0.498135628, 
        'Flow IAT Mean': 2509356.75, 'Flow IAT Max': 10000000, 'Packet Length Mean': 6.0, 
        'Packet Length Std': 0.0, 'Average Packet Size': 7.2, 'SYN Flag Count': 0, 
        'ACK Flag Count': 1, 'PSH Flag Count': 0, 'FIN Flag Count': 0
    }, "DDoS"),
    ({
        'Destination Port': 311, 'Flow Duration': 43, 'Total Fwd Packets': 1, 
        'Total Backward Packets': 1, 'Flow Bytes/s': 139534.8837, 'Flow Packets/s': 46511.62791, 
        'Flow IAT Mean': 43.0, 'Flow IAT Max': 43, 'Packet Length Mean': 2.0, 
        'Packet Length Std': 3.464101615, 'Average Packet Size': 3.0, 'SYN Flag Count': 0, 
        'ACK Flag Count': 0, 'PSH Flag Count': 1, 'FIN Flag Count': 0
    }, "PortScan"),
    ({
        'Destination Port': 80, 'Flow Duration': 5837987, 'Total Fwd Packets': 3, 
        'Total Backward Packets': 1, 'Flow Bytes/s': 0.0, 'Flow Packets/s': 0.685167679, 
        'Flow IAT Mean': 1945995.667, 'Flow IAT Max': 5837080, 'Packet Length Mean': 0.0, 
        'Packet Length Std': 0.0, 'Average Packet Size': 0.0, 'SYN Flag Count': 0, 
        'ACK Flag Count': 0, 'PSH Flag Count': 1, 'FIN Flag Count': 0
    }, "Web Attack")
])
def test_predictions(packet, expected):
    result = predict_packet(packet)
    assert result == expected

def test_validation_logic():
    bad_packet = {"Destination Port": 80}
    is_valid, msg = validate_json(bad_packet)
    assert is_valid is False
    assert "Missing keys:" in msg