# 🛡️ Hybrid Intrusion Prevention System (IPS) & Network Analyzer

## 📌 Overview

This project presents a **Hybrid Intrusion Prevention System (IPS)** that integrates signature-based detection with AI-driven anomaly detection to ensure comprehensive network security. It combines traditional **Snort-based** detection with **machine learning models** to identify and prevent both known and novel threats in real time.

---

## 🔍 Key Features

### 🧪 Hybrid Detection Approach
- Signature-based detection with **Snort**
- Anomaly detection using **ML models**
- Real-time traffic monitoring and alerting

### 🤖 AI Module
- Multiple ML models: Random Forest, XGBoost, Neural Networks, etc.
- Custom 3-layer neural architecture
- Continuous learning and retraining support

### 🌐 Network Analysis
- Flow extraction via **CICFlowMeter**
- Real-time traffic capture
- Dataset collection for training purposes

### 🐳 Deployment
- Containerized with **Docker**
- Modular architecture for easy scalability
- Compatible with multiple platforms

---

## 🧱 System Architecture

- **Core IPS Engine** (Go)
  - Packet inspection, iptables integration, alert generation
- **AI Server** (Python)
  - Hosts ML models, serves classifications, retrains models
- **GUI Interface** (Next.js)
  - Dashboard, alert management, traffic control
- **Attack Tools**
  - Simulates various attack types and benign traffic

---

## 🧠 Machine Learning Models

### 🏷️ Traditional
- Logistic Regression
- SVM
- K-Nearest Neighbors
- Naïve Bayes

### 🌲 Ensemble
- Random Forest
- Gradient Boosting
- XGBoost, LightGBM, CatBoost

### 🧠 Neural Networks
- Custom 3-layer model with dropout and sigmoid activation

---

## 📊 Performance Metrics

Evaluation includes:
- Accuracy
- Precision / Recall
- F1-Score
- False Positive Rate (FPR)
- True Positive Rate (TPR)

---

## 🚀 Getting Started

### ✅ Prerequisites
- Docker & Docker Compose
- Python 3.x
- Go 1.23+
- Node.js

### 🛠 Installation
```bash
# Clone the repository
git clone https://github.com/your-repo/hybrid-ips.git
cd hybrid-ips

# Build and start containers
docker-compose up --build
```

- Set up environment variables in `.env`
- Start IPS core, AI server, and GUI

---

## 💻 Usage

- Access GUI at: `http://localhost:3000`
- Choose detection mode:
  - Signature-only
  - AI-only
  - Hybrid
- View alerts and manage blocked IPs

---

## 🧪 Testing

```bash
# Simulate attacks
docker exec -it attacker-container ./scripts/run_attacks.sh

# Generate benign traffic
docker exec -it attacker-container ./scripts/run_benign.sh
```

---

## 📈 Results

- Detection Accuracy: **>96%**
- False Positive Rate: **<4%**
- Real-time detection with high reliability
- Excellent synergy between Snort and ML components

---

## 🔮 Future Work

- Add more attack types
- Improve ML generalization
- Adaptive learning modules
- Extend to cloud-native deployment

---
