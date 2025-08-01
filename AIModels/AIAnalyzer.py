import joblib
from tensorflow.keras.models import load_model
import socket
import json
import os
from typing import List, Dict
import pandas as pd

# Feature names for input dimension (if needed)
feature_names = ['Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                 'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
                 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
                 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
                 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Fwd IAT Mean',
                 'Fwd IAT Std', 'Bwd IAT Mean', 'Bwd IAT Std', 'Fwd Packets/s',
                 'Bwd Packets/s', 'Packet Length Mean', 'Packet Length Std',
                 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
                 'ACK Flag Count', 'URG Flag Count', 'Fwd Avg Bytes/Bulk',
                 'Fwd Avg Packets/Bulk', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
                 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
                 'Subflow Bwd Bytes', 'Active Mean', 'Idle Mean']

def load_models_and_scaler(model_dir: str = './models'):
    """
    Returns (models_dict, scaler, keras_model).
    """
    models = {}
    for fname in os.listdir(model_dir):
        if (fname.endswith('.joblib') or fname.endswith('.pkl')) and fname not in ('nn_scaler.pkl', 'nn_scaler.joblib'):
            model_name = fname.rsplit('.', 1)[0]
            models[model_name] = joblib.load(os.path.join(model_dir, fname))
    print(f"Loaded sklearn models: {list(models.keys())}")

    scaler_path_joblib = os.path.join(model_dir, 'nn_scaler.joblib')
    scaler_path_pkl = os.path.join(model_dir, 'nn_scaler.pkl')

    if os.path.exists(scaler_path_joblib):
        scaler = joblib.load(scaler_path_joblib)
    elif os.path.exists(scaler_path_pkl):
        scaler = joblib.load(scaler_path_pkl)
    else:
        raise FileNotFoundError("Scaler file 'nn_scaler' not found in model directory.")

    keras_model_path = os.path.join(model_dir, 'nn_model.h5')
    if not os.path.exists(keras_model_path):
        raise FileNotFoundError("Keras model 'nn_model.h5' not found in model directory.")
    keras_model = load_model(keras_model_path)

    return models, scaler, keras_model

def predict_sklearn(models: Dict[str, object], features: List[float]) -> List[int]:
    X = pd.DataFrame([features], columns=feature_names)
    predictions = []
    for model in models.values():
        pred = int(model.predict(X)[0])
        predictions.append(pred)
    return predictions

def predict_keras(keras_model, scaler, features: List[float]) -> int:
    X = pd.DataFrame([features], columns=feature_names)

    X_scaled = scaler.transform(X)
    prob = keras_model.predict(X_scaled, verbose=0)[0, 0]
    return int(prob >= 0.5)

def handle_client(client_socket: socket.socket, models, scaler, keras_model):
    try:
        data = client_socket.recv(8192)
        if not data:
            return

        features = json.loads(data.decode('utf-8'))
        features = [float(x) for x in features]
        predictions = predict_sklearn(models, features)
        nn_prediction = predict_keras(keras_model, scaler, features)

        predictions.append(nn_prediction)  # Append neural net prediction

        client_socket.sendall(json.dumps(predictions).encode('utf-8'))
    except Exception as e:
        error_msg = {'error': str(e)}
        client_socket.sendall(json.dumps(error_msg).encode('utf-8'))
        print(f"[ERROR] {e}")
    finally:
        client_socket.close()

def start_server(host: str = '0.0.0.0', port: int = 50051, backlog: int = 50):
    """
    Bootstraps the TCP server and handles incoming connections.
    """
    models, scaler, keras_model = load_models_and_scaler()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.bind((host, port))
        server_sock.listen(backlog)
        print(f"🔹 Server listening on {host}:{port} (backlog={backlog})...")

        while True:
            client_sock, addr = server_sock.accept()
            print(f"[INFO] Connection from {addr}")
            handle_client(client_sock, models, scaler, keras_model)


if __name__ == '__main__':
    start_server(host='172.30.0.11', port=50051)
