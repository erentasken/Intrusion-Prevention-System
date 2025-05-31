import os
import time
import signal
import subprocess
import pandas as pd
import numpy as np
import joblib
import json
import sys
from scapy.all import sniff, wrpcap
import logging

# Configure logging to stderr only
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

IFACE = "eth0"
BUFFER_SECONDS = 5
PCAP_PATH = "/tmp/buffer.pcap"
CIC_PATH = "/app/service/CICFlowMeter-4.0/bin/CICFlowMeter"
OUTPUT_DIR = "/app/service/csv"

RAW_CSV_PATH = os.path.join(OUTPUT_DIR, "buffer_ISCX.csv")
FILTERED_CSV_PATH = os.path.join(OUTPUT_DIR, "flows_filtered.csv")

SAVED_MODELS_DIR = "/app/service/saved_models"

stop_capture = False

def signal_handler(sig, frame):
    global stop_capture
    logging.info("👋 Stopping capture requested.")
    stop_capture = True

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def capture_packets(duration, iface, pcap_file):
    logging.info(f"📡 Capturing packets on {iface} for {duration} seconds...")
    try:
        packets = sniff(iface=iface, timeout=duration)
        if len(packets) == 0:
            logging.warning("⚠️ No packets captured during this interval.")
        wrpcap(pcap_file, packets)
        logging.info(f"💾 Saved {len(packets)} packets to {pcap_file}")
        return len(packets) > 0
    except Exception as e:
        logging.error(f"❌ Error capturing packets: {e}")
        return False

def run_cicflowmeter(pcap_file, output_dir, cic_path):
    logging.info("🔄 Running CICFlowMeter on captured buffer...")
    try:
        result = subprocess.run([cic_path, pcap_file, output_dir], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            logging.error(f"❌ CICFlowMeter failed:\n{result.stderr.strip()}")
            return False
        logging.info("✅ Flow CSV created.")
        return True
    except subprocess.TimeoutExpired:
        logging.error("❌ CICFlowMeter process timed out.")
        return False
    except Exception as e:
        logging.error(f"❌ CICFlowMeter execution error: {e}")
        return False

def load_models():
    # Load once outside loop
    try:
        le = joblib.load(os.path.join(SAVED_MODELS_DIR, "label_encoder.joblib"))
        scaler = joblib.load(os.path.join(SAVED_MODELS_DIR, "scaler.joblib"))
        feature_columns = joblib.load(os.path.join(SAVED_MODELS_DIR, "feature_columns.joblib"))
        logging.info("✅ Loaded label encoder, scaler, and feature columns.")
    except Exception as e:
        logging.error(f"❌ Failed to load preprocessing artifacts: {e}")
        return None, None, None, None

    models = {}
    for file in os.listdir(SAVED_MODELS_DIR):
        if file.endswith(".joblib") and not file.startswith(("label_encoder", "scaler", "feature_columns")):
            model_path = os.path.join(SAVED_MODELS_DIR, file)
            model_name = file.replace(".joblib", "").replace("_", " ").title()
            try:
                model = joblib.load(model_path)
                models[model_name] = model
            except Exception as e:
                logging.warning(f"⚠️ Failed to load model {model_name}: {e}")

    return le, scaler, feature_columns, models

def predict(le, scaler, feature_columns, models, filtered_csv):
    if not os.path.isfile(filtered_csv):
        logging.warning(f"⚠️ File not found: {filtered_csv}")
        return

    df = pd.read_csv(filtered_csv)
    if df.empty or 'Src IP' not in df.columns:
        logging.warning(f"⚠️ Invalid or empty input CSV.")
        return

    # Drop first row once (usually metadata)
    df = df.drop(index=0).reset_index(drop=True)

    if df.empty:
        logging.warning("⚠️ DataFrame is empty after dropping the first row.")
        return

    attacker_ips = df['Src IP'].values
    X_raw = df.drop(columns=['Src IP'])

    # Coerce all values to numeric, turning invalid ones to NaN
    X_raw = X_raw.apply(pd.to_numeric, errors='coerce')

    # Drop rows with all NaNs (or you may choose to fillna(0))
    X_raw = X_raw.dropna(how='all')

    # Add missing features
    for col in feature_columns:
        if col not in X_raw.columns:
            X_raw[col] = 0

    # Reorder to match feature columns
    X_raw = X_raw[feature_columns]

    X_new = X_raw.select_dtypes(include=[np.number])

    try:
        X_scaled = scaler.transform(X_new)
        logging.info("✅ Applied scaler on input data.")
    except Exception as e:
        logging.error(f"❌ Error during scaling: {e}")
        return

    # Predict only first 5 samples to limit output
    X_scaled_subset = X_scaled[:5]
    ip_subset = attacker_ips[:5]

    if not models:
        logging.warning("⚠️ No models loaded for prediction.")
        return

    output_predictions = []

    for model_name, model in models.items():
        try:
            y_pred = model.predict(X_scaled_subset)
            decoded = le.inverse_transform(y_pred)
            for i, pred in enumerate(decoded):
                output_predictions.append({
                    "Attacker_ip": attacker_ips[i],
                    "Message": pred
                })
        except Exception as e:
            logging.error(f"❌ Failed to predict with {model_name}: {e}")

    # Output JSON predictions to stdout
    print(json.dumps(output_predictions), flush=True)

def StartUNSW():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    global stop_capture

    stop_capture = False

    le, scaler, feature_columns, models = load_models()
    if le is None:
        logging.error("Exiting: Failed to load necessary artifacts.")
        return

    while not stop_capture:
        # Remove old pcap file
        if os.path.exists(PCAP_PATH):
            try:
                os.remove(PCAP_PATH)
                logging.info(f"🧹 Removed old pcap file {PCAP_PATH}")
            except Exception as e:
                logging.warning(f"⚠️ Could not remove old pcap file: {e}")

        # Remove old CSV files before new CICFlowMeter run
        for file in [RAW_CSV_PATH, FILTERED_CSV_PATH]:
            if os.path.exists(file):
                try:
                    os.remove(file)
                    logging.info(f"🧹 Removed old CSV file {file}")
                except Exception as e:
                    logging.warning(f"⚠️ Could not remove old CSV file {file}: {e}")

        success = capture_packets(BUFFER_SECONDS, IFACE, PCAP_PATH)
        if not success:
            logging.warning("Skipping this cycle due to no captured packets.")
            time.sleep(1)
            continue

        if not run_cicflowmeter(PCAP_PATH, OUTPUT_DIR, CIC_PATH):
            logging.warning("Skipping filtering and prediction due to CICFlowMeter error.")
            time.sleep(1)
            continue

        predict(le, scaler, feature_columns, models, RAW_CSV_PATH)

        logging.info("⏳ Waiting before next capture cycle...\n")
        time.sleep(1)

    logging.info("👋 Exiting program.")

if __name__ == "__main__":
    StartUNSW()
