import json
import socket
import joblib
import numpy as np
import tensorflow as tf
import torch
from NNModel import BinaryClassifier

from concurrent.futures import ThreadPoolExecutor

# Define feature names
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

# Load Models
def load_models_scaler():
    model_names = [
        'SVM', 'Random Forest', 'Logistic Regression',
        'Gradient Boosting', 'XGBoost', 'KNN', 'Naïve Bayes'
    ]
    models = [joblib.load(f'./models/{model}.pkl') for model in model_names]
    return models

def predict(features, models):
    features_reshaped = np.array(features).reshape(1, -1)
    
    # Use ThreadPoolExecutor to parallelize predictions
    with ThreadPoolExecutor(max_workers=len(models)) as executor:
        predictions = list(executor.map(lambda model: int(model.predict(features_reshaped)[0]), models))
    
    return predictions


#     return int((predictions > 0.5).astype(int)[0, 0])  # Ensure a single integer output

def predict_nn(features, scaler, model):
    new_data = np.array(features).reshape(1, -1)
    new_data_scaled = scaler.transform(new_data)
    with torch.no_grad():
        prob = model(torch.FloatTensor(new_data_scaled))
        prediction = (prob > 0.5).int()
        return int(prediction), prob.item()

# Start Socket Server
def start_server():
    # Load models and scaler
    models = load_models_scaler()

    nnModel = BinaryClassifier(input_size=len(feature_names))
    nnModel.load_state_dict(torch.load('./models/nn.pth'))
    nnModel.eval()
    nnScaler = joblib.load('./models/scaler.pkl')

    # Set up the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('172.30.0.11', 50051))
    server_socket.listen(50)  # Allow up to 5 queued connections
    
    print("🔹 Server listening on port 50051...")

    while True:
        # Accept client connection
        client_socket, client_address = server_socket.accept()
        
        try:
            # Receive the data from the client
            data = client_socket.recv(4096)  # Increased buffer size
            if not data:
                continue  # Avoid breaking the loop

            # Deserialize the received JSON data
            features = json.loads(data.decode('utf-8'))
            
            # Ensure received features are numerical
            features = [float(x) for x in features]

            # Get predictions from models
            predictions = predict(features, models)
            nn_prediction, prob = predict_nn(features, nnScaler, nnModel)

            # Append the NN prediction
            predictions.append(nn_prediction)

            # Send predictions back to the client
            response = json.dumps(predictions)
            client_socket.sendall(response.encode('utf-8'))  # Send all data properly

        except Exception as e:
            print(f"Error processing request: {e}")
            client_socket.sendall(json.dumps({"error": str(e)}).encode('utf-8'))

        finally:
            # Close the client connection
            client_socket.close()

# Run the server
if __name__ == '__main__':
    start_server()
