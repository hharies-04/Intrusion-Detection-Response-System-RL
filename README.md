# AIDRS: Adaptive Intrusion Detection & Response System

## 🛡️ Overview

**AIDRS** is a sophisticated network security system that combines **Machine Learning** for intrusion detection with **Reinforcement Learning** for adaptive response selection. The system captures live network traffic, analyzes packets for attacks, and automatically decides the optimal response action (Allow, Alert, or Block).

### Key Components

1. **Packet Capture Layer** (`sniffer_enhanced.py`)
   - Real-time network traffic sniffing using Scapy
   - Windows-compatible via Npcap
   - Feature extraction for ML analysis

2. **ML Detection Layer** (`ids_model_trainer.py`)
   - Trains intrusion detection models (RandomForest, SVM, GradientBoosting)
   - Binary classification: Benign vs Attack
   - Confidence-based severity assessment

3. **RL Response Layer** (`dqn_agent.py`)
   - Deep Q-Network (DQN) for response selection
   - Learns optimal actions: Allow, Alert, Block
   - Experience-based learning with reward structure

4. **Dashboard** (`dashboard_enhanced.py`)
   - Real-time monitoring with Streamlit
   - Manual prediction & testing
   - DQN agent training interface
   - Analytics & reporting

## ⚙️ Installation

### Prerequisites

- Python 3.8+
- Windows (for Npcap) or Linux
- Administrator privileges for packet capture

### Setup Steps

```bash
# Clone or download the AIDRS codebase
cd AIDRS

# Install dependencies
pip install -r requirements.txt

# For Windows packet capture, install Npcap
# Download from: https://npcap.com/dist/npcap-1.60.exe
```

### Verify Installation

```bash
python -c "import scapy; import torch; import streamlit; print('✅ All dependencies installed')"
```

## 🚀 Quick Start

### 1. Initialize AIDRS

```bash
python aidrs_config.py init
```

### 2. Train ML Detection Model

If you have training data (CSV with features and 'Label' column):

```bash
python aidrs_config.py train-ids --data your_data.csv --model random_forest
```

Or use the demo:

```bash
python aidrs_config.py demo
```

### 3. Run Dashboard

```bash
streamlit run dashboard_enhanced.py
```

The dashboard will open at `http://localhost:8501`

## 📊 Using the Dashboard

### Tab 1: Live Events
- Start/stop the sniffer
- View real-time network events
- Monitor attack statistics
- Download event logs

### Tab 2: Analytics
- Traffic distribution by protocol
- Packet size analysis
- Attack timeline
- Most active sources

### Tab 3: Manual Prediction
- Test the system with custom inputs
- Get ML verdict and RL response
- Understand decision reasoning

### Tab 4: RL Training
- Add training experiences
- Train DQN agent on batches
- Monitor learning progress
- Save trained models

### Tab 5: Offline Analysis
- Upload CSV files for analysis
- Post-incident investigation
- Historical data exploration

## 🤖 Machine Learning Models

### Supported IDS Models

```python
# RandomForest (Default - Recommended)
trainer = IDSModelTrainer(model_type='random_forest')

# Support Vector Machine
trainer = IDSModelTrainer(model_type='svm')

# Gradient Boosting
trainer = IDSModelTrainer(model_type='gradient_boosting')
```

### Training Pipeline

```python
from ids_model_trainer import train_pipeline

trainer = train_pipeline(
    data_path="training_data.csv",
    model_type='random_forest',
    save_models=True
)
```

## 🎯 Deep Q-Network (DQN) Agent

### DQN Architecture

```
State: [attack_type, severity, confidence, flow_size, protocol, src_encoded, dst_encoded, padding]
       ↓
    [FC 64] → ReLU
       ↓
    [FC 64] → ReLU
       ↓
    [FC 3] → Q-Values (Allow=0, Alert=1, Block=2)
```

### Training Experience

```python
from dqn_agent import DQNAgent, calculate_reward

agent = DQNAgent(state_size=8, action_size=3)

# Add experience
state = np.array([0.5, 0.7, 0.85, ...])
action = 2  # Block
reward = calculate_reward(action=2, actual_label=1, confidence=0.85)
next_state = np.array([0.5, 0.7, 0.85, ...])
done = False

agent.remember(state, action, reward, next_state, done)

# Train
loss = agent.replay(batch_size=32)
agent.update_target_network()
agent.save("dqn_agent.pt")
```

### Reward Structure

```
Block/Alert Attack:     +10 × confidence
Allow Attack:          -5 × confidence
Allow Benign:          +2 × confidence
Alert Benign:          -1 × confidence
Block Benign:          -3 × confidence
```

## 📝 Data Formats

### Live Events CSV

```csv
timestamp,src_ip,dst_ip,protocol,length,summary,verdict,confidence
2024-01-15 10:30:45,192.168.1.100,10.0.0.1,TCP,1200,..SYN..,Suspicious,0.72
2024-01-15 10:30:46,192.168.1.101,10.0.0.2,UDP,60,QUIC,Benign,0.95
```

### Blocklist JSON

```json
[
  "192.168.1.100",
  "192.168.1.101",
  "10.5.5.5"
]
```

### Training Data CSV

```csv
Feature1,Feature2,Feature3,...,FeatureN,Label
0.5,0.7,1200,...,64,Benign
0.8,0.3,2000,...,128,Attack
```

Required columns:
- Multiple feature columns (numeric)
- `Label` column (Benign/Attack or 0/1)

## 🔧 Configuration

Edit `aidrs_config.py` to customize:

```python
class AIConfig:
    # Model paths
    IDS_MODEL = "trained_ids_model.pkl"
    DQN_MODEL = "dqn_agent.pt"
    
    # Model hyperparameters
    IDS_MODEL_TYPE = "random_forest"
    IDS_TEST_SIZE = 0.2
    
    # DQN hyperparameters
    DQN_STATE_SIZE = 8
    DQN_ACTION_SIZE = 3
    DQN_LEARNING_RATE = 0.001
    DQN_GAMMA = 0.95
    DQN_EPSILON_DECAY = 0.995
    
    # Sniffer
    SNIFFER_IFACE = r"\Device\NPF_{YOUR_INTERFACE_GUID}"
```

## 🛠️ Advanced Usage

### Custom Feature Extraction

```python
from utilities import NetworkFeatureExtractor

extractor = NetworkFeatureExtractor()

# Extract flow features
features = extractor.extract_flow_features(packets)

# Extract single packet features
pkt_features = extractor.extract_packet_features(packet)
```

### Alert Management

```python
from utilities import AlertManager

alerts = AlertManager()

# Create alert
alerts.add_alert(
    alert_type="Port Scan",
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    severity="high",
    description="SYN flood detected"
)

# Get critical alerts
critical = alerts.get_critical_alerts()
```

### Security Metrics

```python
from utilities import SecurityMetrics

# Calculate attack ratio
ratio = SecurityMetrics.calculate_attack_ratio(events_df)

# Get top attackers
top_attackers = SecurityMetrics.calculate_top_attackers(events_df, top_k=10)

# Get response rate
responses = SecurityMetrics.calculate_response_rate(events_df)
```

## 📈 Performance Metrics

The system tracks and logs:

- **Detection Accuracy:** IDS model F1-score on test set
- **Response Coverage:** % of events with RL response
- **False Positive Rate:** Benign traffic incorrectly flagged
- **True Positive Rate:** Attacks correctly detected
- **DQN Learning Progress:** Average reward per episode

Monitor in Dashboard → Analytics tab

## 🐛 Troubleshooting

### "Permission Denied" on Sniffer

**Solution:** Run as Administrator
```bash
python -m pip install --upgrade pip
python dashboard_enhanced.py  # Run as Admin
```

### Npcap Not Found (Windows)

**Solution:** Install Npcap
1. Download: https://npcap.com/
2. Run installer as Administrator
3. Select "Install Npcap in WinPcap API-compatible mode"

### Model Load Errors

**Solution:** Check file paths in `aidrs_config.py`
```bash
python -c "from pathlib import Path; print(Path('trained_ids_model.pkl').exists())"
```

### GPU Out of Memory

**Solution:** Reduce DQN batch size in `aidrs_config.py`
```python
DQN_BATCH_SIZE = 16  # Reduce from 32
```

## 📚 Example Workflow

```python
# 1. Train IDS Model
from ids_model_trainer import IDSModelTrainer

trainer = IDSModelTrainer(model_type='random_forest')
X_train, X_test, y_train, y_test = trainer.load_data("training_data.csv")
trainer.train(X_train, y_train)
trainer.evaluate(X_test, y_test)
trainer.save()

# 2. Train DQN Agent
from dqn_agent import DQNAgent, calculate_reward

agent = DQNAgent()
for episode in range(100):
    state = sample_state()
    action = agent.act(state, training=True)
    reward = calculate_reward(action, ground_truth, confidence)
    next_state = observe_next_state()
    agent.remember(state, action, reward, next_state, done)
    agent.replay(32)

agent.save("dqn_agent.pt")

# 3. Run Live System
# Open terminal and run:
# streamlit run dashboard_enhanced.py
# Then click "Start Sniffer" in sidebar
```

## 📖 File Structure

```
AIDRS/
├── dqn_agent.py                 # DQN Agent implementation
├── ids_model_trainer.py         # ML model training
├── sniffer_enhanced.py          # Packet capture
├── dashboard_enhanced.py        # Streamlit UI
├── utilities.py                 # Helper functions
├── aidrs_config.py             # Configuration & CLI
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── .github/
│   └── copilot-instructions.md # AI agent guide
├── live_events.csv             # Real-time events log
├── blocklist.json              # Blocked IPs
├── trained_ids_model.pkl       # Saved ML model
├── dqn_agent.pt               # Saved DQN agent
└── alerts.json                # Alert log
```

## 🔒 Security Best Practices

1. **Run Sniffer as Administrator** - Required for packet capture
2. **Validate Training Data** - Ensure labeled data quality
3. **Regular Model Retraining** - Update models with new attack patterns
4. **Monitor Alerts** - Check high-confidence detections
5. **Backup Blocklist** - Keep copies of blocked IPs
6. **Isolate Test Network** - Test on non-production traffic

## 📄 License

AIDRS is provided as-is for educational and research purposes.

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- [ ] Additional ML models (Neural Networks, Random Forests optimization)
- [ ] Multi-threading for packet processing
- [ ] Database backend for event storage
- [ ] REST API for integration
- [ ] Mobile dashboard
- [ ] Distributed agent deployment

## ❓ FAQ

**Q: Can this run on Linux?**
A: Yes, but requires different packet capture library (tcpdump) and network interface configuration.

**Q: What dataset should I use for training?**
A: CICIDS2018, UNSW-NB15, or NSL-KDD are common choices. Ensure columns include network flow features.

**Q: How do I integrate with a firewall?**
A: Modify `sniffer_enhanced.py` to execute OS commands (iptables on Linux, netsh on Windows).

**Q: Can I use this in production?**
A: This is a research system. For production, add proper logging, monitoring, and integrate with SIEM tools.

## 📧 Contact & Support

For issues, questions, or feature requests, create an GitHub issue or contact the development team.

---

**Last Updated:** December 2024
**Version:** 1.0.0
