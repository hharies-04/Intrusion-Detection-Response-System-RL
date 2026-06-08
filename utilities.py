"""
Utility Functions and Feature Extraction for AIDRS
Provides data processing, feature engineering, and helper functions
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from scapy.all import IP, TCP, UDP, ICMP
import json
from pathlib import Path
from datetime import datetime
import ipaddress


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

class NetworkFeatureExtractor:
    """Extract advanced network features from packets for ML models."""
    
    @staticmethod
    def extract_flow_features(packets: list) -> dict:
        """
        Extract statistical features from a flow (multiple packets).
        
        Args:
            packets: List of Scapy packet objects
        
        Returns:
            Dictionary of flow features
        """
        if not packets:
            return {}
        
        features = {
            'flow_duration': 0,
            'total_fwd_packets': 0,
            'total_bwd_packets': 0,
            'total_fwd_bytes': 0,
            'total_bwd_bytes': 0,
            'fwd_packet_length_max': 0,
            'fwd_packet_length_min': float('inf'),
            'fwd_packet_length_avg': 0,
            'bwd_packet_length_max': 0,
            'bwd_packet_length_min': float('inf'),
            'bwd_packet_length_avg': 0,
            'flow_packets_per_sec': 0,
            'flow_bytes_per_sec': 0,
            'flow_iat_mean': 0,
            'flow_iat_max': 0,
            'flow_iat_min': 0,
            'fwd_iat_mean': 0,
            'fwd_iat_max': 0,
            'fwd_iat_min': 0,
            'bwd_iat_mean': 0,
            'bwd_iat_max': 0,
            'bwd_iat_min': 0,
            'fwd_psh_flags': 0,
            'bwd_psh_flags': 0,
            'fwd_urg_flags': 0,
            'bwd_urg_flags': 0,
            'fwd_rst_flags': 0,
            'bwd_rst_flags': 0,
            'fwd_syn_flags': 0,
            'bwd_syn_flags': 0,
            'fwd_fin_flags': 0,
            'bwd_fin_flags': 0,
            'fwd_ack_flags': 0,
            'bwd_ack_flags': 0,
            'init_fwd_win_byts': 0,
            'init_bwd_win_byts': 0,
            'active_mean': 0,
            'active_max': 0,
            'active_min': 0,
            'idle_mean': 0,
            'idle_max': 0,
            'idle_min': 0,
        }
        
        fwd_lengths = []
        bwd_lengths = []
        fwd_iats = []
        bwd_iats = []
        all_iats = []
        
        prev_time = None
        prev_fwd_time = None
        prev_bwd_time = None
        src_ip = None
        
        for i, pkt in enumerate(packets):
            if IP not in pkt:
                continue
            
            pkt_len = len(pkt)
            pkt_time = pkt.time if hasattr(pkt, 'time') else i * 0.001
            
            if i == 0:
                src_ip = pkt[IP].src
                features['init_fwd_win_byts'] = pkt[TCP].window if TCP in pkt else 0
            
            # Determine direction (forward if src matches initial src_ip)
            is_fwd = pkt[IP].src == src_ip
            
            if is_fwd:
                features['total_fwd_packets'] += 1
                features['total_fwd_bytes'] += pkt_len
                fwd_lengths.append(pkt_len)
                if prev_fwd_time:
                    iat = pkt_time - prev_fwd_time
                    fwd_iats.append(iat)
                prev_fwd_time = pkt_time
                
                # TCP flags
                if TCP in pkt:
                    if pkt[TCP].flags.P:
                        features['fwd_psh_flags'] += 1
                    if pkt[TCP].flags.U:
                        features['fwd_urg_flags'] += 1
                    if pkt[TCP].flags.R:
                        features['fwd_rst_flags'] += 1
                    if pkt[TCP].flags.S:
                        features['fwd_syn_flags'] += 1
                    if pkt[TCP].flags.F:
                        features['fwd_fin_flags'] += 1
                    if pkt[TCP].flags.A:
                        features['fwd_ack_flags'] += 1
            else:
                features['total_bwd_packets'] += 1
                features['total_bwd_bytes'] += pkt_len
                bwd_lengths.append(pkt_len)
                if prev_bwd_time:
                    iat = pkt_time - prev_bwd_time
                    bwd_iats.append(iat)
                prev_bwd_time = pkt_time
                features['init_bwd_win_byts'] = pkt[TCP].window if TCP in pkt else features['init_bwd_win_byts']
                
                # TCP flags
                if TCP in pkt:
                    if pkt[TCP].flags.P:
                        features['bwd_psh_flags'] += 1
                    if pkt[TCP].flags.U:
                        features['bwd_urg_flags'] += 1
                    if pkt[TCP].flags.R:
                        features['bwd_rst_flags'] += 1
                    if pkt[TCP].flags.S:
                        features['bwd_syn_flags'] += 1
                    if pkt[TCP].flags.F:
                        features['bwd_fin_flags'] += 1
                    if pkt[TCP].flags.A:
                        features['bwd_ack_flags'] += 1
            
            # Inter-arrival time
            if prev_time:
                all_iats.append(pkt_time - prev_time)
            prev_time = pkt_time
        
        # Calculate aggregates
        if fwd_lengths:
            features['fwd_packet_length_max'] = max(fwd_lengths)
            features['fwd_packet_length_min'] = min(fwd_lengths)
            features['fwd_packet_length_avg'] = np.mean(fwd_lengths)
        
        if bwd_lengths:
            features['bwd_packet_length_max'] = max(bwd_lengths)
            features['bwd_packet_length_min'] = min(bwd_lengths)
            features['bwd_packet_length_avg'] = np.mean(bwd_lengths)
        
        if all_iats:
            features['flow_iat_mean'] = np.mean(all_iats)
            features['flow_iat_max'] = max(all_iats)
            features['flow_iat_min'] = min(all_iats)
        
        if fwd_iats:
            features['fwd_iat_mean'] = np.mean(fwd_iats)
            features['fwd_iat_max'] = max(fwd_iats)
            features['fwd_iat_min'] = min(fwd_iats)
        
        if bwd_iats:
            features['bwd_iat_mean'] = np.mean(bwd_iats)
            features['bwd_iat_max'] = max(bwd_iats)
            features['bwd_iat_min'] = min(bwd_iats)
        
        return features
    
    @staticmethod
    def extract_packet_features(pkt) -> dict:
        """Extract features from a single packet."""
        features = {
            'packet_length': len(pkt),
            'protocol': 0,
            'src_port': 0,
            'dst_port': 0,
            'tcp_flags': 0,
            'ttl': 0,
            'is_fragmented': 0,
            'tos': 0,
        }
        
        if IP in pkt:
            features['ttl'] = pkt[IP].ttl
            features['tos'] = pkt[IP].tos
            features['is_fragmented'] = 1 if pkt[IP].flags.MF or pkt[IP].frag > 0 else 0
            
            if TCP in pkt:
                features['protocol'] = 6
                features['src_port'] = pkt[TCP].sport
                features['dst_port'] = pkt[TCP].dport
                features['tcp_flags'] = pkt[TCP].flags
            elif UDP in pkt:
                features['protocol'] = 17
                features['src_port'] = pkt[UDP].sport
                features['dst_port'] = pkt[UDP].dport
            elif ICMP in pkt:
                features['protocol'] = 1
            else:
                features['protocol'] = pkt[IP].proto
        
        return features


# ============================================================================
# IP & NETWORK UTILITIES
# ============================================================================

class IPAddressUtils:
    """Utilities for IP address analysis and encoding."""
    
    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if IP is private (RFC 1918)."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except:
            return False
    
    @staticmethod
    def is_reserved_ip(ip_str: str) -> bool:
        """Check if IP is reserved."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_reserved
        except:
            return False
    
    @staticmethod
    def ip_to_int(ip_str: str) -> int:
        """Convert IP address to integer."""
        try:
            return int(ipaddress.ip_address(ip_str))
        except:
            return 0
    
    @staticmethod
    def encode_ip_subnet(ip_str: str) -> dict:
        """Encode IP subnet information."""
        try:
            ip = ipaddress.ip_address(ip_str)
            octets = list(ip.packed)
            return {
                'octet_1': octets[0] / 255.0,
                'octet_2': octets[1] / 255.0,
                'octet_3': octets[2] / 255.0,
                'octet_4': octets[3] / 255.0,
            }
        except:
            return {'octet_1': 0, 'octet_2': 0, 'octet_3': 0, 'octet_4': 0}


# ============================================================================
# DATA PREPROCESSING
# ============================================================================

class DataPreprocessor:
    """Preprocess network traffic data for ML models."""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_names = None
    
    def prepare_training_data(self, csv_path: str, label_column='Label'):
        """
        Load and prepare data from CSV for training.
        
        Args:
            csv_path: Path to CSV file
            label_column: Name of target column
        
        Returns:
            X, y, feature_names
        """
        df = pd.read_csv(csv_path)
        
        # Separate features and labels
        X = df.drop(columns=[label_column])
        y = df[label_column]
        
        # Handle missing values
        X = X.fillna(X.mean(numeric_only=True))
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        self.feature_names = X.columns.tolist()
        
        return X_scaled, y, self.feature_names
    
    def normalize_packet_features(self, features: dict) -> np.ndarray:
        """Normalize extracted packet features."""
        # Convert to feature vector in expected order
        feature_vector = np.array([
            features.get('packet_length', 0),
            features.get('protocol', 0),
            features.get('src_port', 0),
            features.get('dst_port', 0),
            features.get('tcp_flags', 0),
            features.get('ttl', 64),
            features.get('is_fragmented', 0),
            features.get('tos', 0),
        ]).reshape(1, -1)
        
        return self.scaler.transform(feature_vector) if self.scaler else feature_vector


# ============================================================================
# ALERT & LOGGING
# ============================================================================

class AlertManager:
    """Manage security alerts and notifications."""
    
    def __init__(self, alert_log_path="alerts.json"):
        self.alert_log_path = alert_log_path
        self.alerts = self.load_alerts()
    
    def load_alerts(self) -> list:
        """Load alerts from JSON log."""
        if Path(self.alert_log_path).exists():
            try:
                with open(self.alert_log_path, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def save_alerts(self):
        """Save alerts to JSON log."""
        with open(self.alert_log_path, 'w') as f:
            json.dump(self.alerts, f, indent=2)
    
    def add_alert(self, alert_type: str, src_ip: str, dst_ip: str, 
                  severity: str, description: str):
        """Add a new alert."""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'severity': severity,
            'description': description,
        }
        self.alerts.append(alert)
        self.save_alerts()
    
    def get_critical_alerts(self) -> list:
        """Get high/critical severity alerts."""
        return [a for a in self.alerts if a.get('severity') in ['high', 'critical']]
    
    def clear_old_alerts(self, days=7):
        """Remove alerts older than specified days."""
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(days=days)
        self.alerts = [
            a for a in self.alerts
            if datetime.fromisoformat(a['timestamp']) > cutoff
        ]
        self.save_alerts()


# ============================================================================
# METRICS & STATISTICS
# ============================================================================

class SecurityMetrics:
    """Calculate security metrics from traffic data."""
    
    @staticmethod
    def calculate_attack_ratio(events_df: pd.DataFrame) -> float:
        """Calculate percentage of attack events."""
        if events_df.empty:
            return 0.0
        attack_count = len(events_df[events_df['verdict'].str.lower() == 'attack'])
        return (attack_count / len(events_df)) * 100
    
    @staticmethod
    def calculate_top_attackers(events_df: pd.DataFrame, top_k=10) -> dict:
        """Get most active attacking IPs."""
        if events_df.empty:
            return {}
        attacks = events_df[events_df['verdict'].str.lower() == 'attack']
        return attacks['src_ip'].value_counts().head(top_k).to_dict()
    
    @staticmethod
    def calculate_response_rate(events_df: pd.DataFrame) -> dict:
        """Calculate response action distribution."""
        if events_df.empty:
            return {'allow': 0, 'alert': 0, 'block': 0}
        
        # If response column exists
        if 'response' in events_df.columns:
            responses = events_df['response'].value_counts()
            return {
                'allow': responses.get('allow', 0),
                'alert': responses.get('alert', 0),
                'block': responses.get('block', 0),
            }
        return {'allow': 0, 'alert': 0, 'block': 0}
